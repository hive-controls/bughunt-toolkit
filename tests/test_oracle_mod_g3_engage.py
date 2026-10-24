"""Characterization oracle for the G3 engagement modules: roost, quill, blaze, diff, clutch.

Written BEFORE the clean-room rebuild (M2 built-in modules, Wave A). It pins the observable
behavior of `bughunt.modules.{roost,quill,blaze,diff,clutch}` as of the tree this branch was cut
from, so an implementer who never reads those files still has a real contract: inputs -> outputs,
the on-disk formats (notes.txt / marks.txt / requests/ / responses/), the argparse forms the
console and the JSON catalog derive from, the colour/banner bytes, and the exit codes.

Labels (same convention as tests/test_workspace_core.py):
  pinned_current_defect  the CURRENT behavior is wrong but is deliberately reproduced by the
                         rebuild; the matching `test_defect_*` xfail states the correct behavior.
  test_defect_*          xfail(...) asserting the CORRECT behavior. An XPASS means the defect was
                         fixed: delete the marker and its `pinned_current_defect` twin.

Isolation: every test runs against a scratch workspace through BUGHUNT_SCOPE with a scratch cwd.
The only network double is a real loopback HTTP server (the `lab` fixture) behind a verified
policy file; modules that must never touch the network run under the `no_network` guard.
"""

from __future__ import annotations

import dataclasses
import inspect
import io
import json
import re
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from bughunt.console import loader, options
from bughunt.core import egress, identity, ledger, scanner, session, workspace
from bughunt.modules import MODULES, blaze, clutch, load_builtin, quill, repeater, roost
from bughunt.modules import diff as diff_cmd
from bughunt.modules.policy import example_document
from test_gate import policy

CYAN = "\x1b[1;96m"
YELLOW = "\x1b[1;93m"
MAGENTA = "\x1b[1;95m"
WHITE = "\x1b[1;97m"
DIM = "\x1b[2;96m"
RESET = "\x1b[0m"

NOTES_HEADER = "# Bughunt notes. One timestamped line each.\n\n"
MARKS_HEADER = "# Bughunt marks. One label and one URL per line.\n\n"
STAMP_FORMAT = "%Y-%m-%d %H:%M:%SZ"
STAMP_PATTERN = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z"


# --------------------------------------------------------------------------------------------
# fixtures and helpers
# --------------------------------------------------------------------------------------------


@pytest.fixture
def ws(monkeypatch, tmp_path):
    root = tmp_path / "ws"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.chdir(tmp_path)
    return root


class _Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def tty(monkeypatch):
    """Factory: call it inside the test body so stdout and stderr look like colour terminals.

    pytest re-points sys.stdout/sys.stderr when the call phase starts, so a fixture-time swap would be undone.
    """

    def install():
        out, err = _Tty(), _Tty()
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", err)
        monkeypatch.setenv("TERM", "xterm")
        return out, err

    return install


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a socket boundary was reached")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)


def call(capsys, module, *argv):
    """Run module.main(argv); return (exit code, stdout, stderr). A SystemExit yields its code."""
    capsys.readouterr()
    try:
        code = module.main(list(argv))
    except SystemExit as stop:
        code = stop.code
    out, err = capsys.readouterr()
    return code, out, err


def put(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return path


def on_disk(path: Path) -> str:
    """File text with platform newlines folded to LF (the modules write with the platform newline)."""
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def utc_stamp(text: str) -> datetime:
    return datetime.strptime(text, STAMP_FORMAT).replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------------------------
# registry, signatures, parser forms: the contract the console and the catalog read
# --------------------------------------------------------------------------------------------

REGISTRY = {
    "roost": "Summarize workspace totals and identify URL hosts lacking scope permission.",
    "clutch": "Browse captured requests with authentication values concealed.",
    "blaze": "Attach a workspace label to an existing URL entry.",
    "quill": "Write dated engagement notes alongside the captured evidence.",
    "diff": "Contrast response evidence from local files or two permitted URLs.",
}
MODULE_OBJECTS = {
    "roost": roost,
    "clutch": clutch,
    "blaze": blaze,
    "quill": quill,
    "diff": diff_cmd,
}


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_registry_description_is_byte_identical(name):
    assert MODULES[name] == REGISTRY[name]


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_load_builtin_returns_the_module_the_console_runs(name):
    module = load_builtin(name)
    assert module is MODULE_OBJECTS[name]
    assert module.__name__ == f"bughunt.modules.{name}"


PUBLIC_SIGNATURES = {
    "roost": {
        "build_parser": (),
        "main": ("argv",),
        "gather": (),
        "format_report": ("report", "color"),
        "format_banner": ("color",),
    },
    "quill": {
        "build_parser": (),
        "main": ("argv",),
        "notes_path": (),
        "read_notes": (),
        "format_banner": ("color",),
        "format_note": ("stamp", "text", "color"),
    },
    "blaze": {
        "build_parser": (),
        "main": ("argv",),
        "marks_path": (),
        "read_marks": (),
        "format_banner": ("color",),
    },
    "diff": {
        "build_parser": (),
        "main": ("argv",),
        "load_side": ("value", "http"),
        "parse_saved": ("data",),
        "render_diff": ("left", "right"),
    },
    "clutch": {
        "build_parser": (),
        "main": ("argv",),
        "list_requests": (),
        "redact": ("data",),
        "format_banner": ("color",),
        "format_row": ("row", "color"),
    },
}


@pytest.mark.parametrize(
    "name,function", [(n, f) for n, group in PUBLIC_SIGNATURES.items() for f in group]
)
def test_public_function_parameter_names(name, function):
    parameters = inspect.signature(getattr(MODULE_OBJECTS[name], function)).parameters
    assert tuple(parameters) == PUBLIC_SIGNATURES[name][function]


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_main_takes_one_optional_argv_defaulting_to_none(name):
    parameter = inspect.signature(MODULE_OBJECTS[name].main).parameters["argv"]
    assert parameter.default is None
    assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD


@pytest.mark.parametrize(
    "name,tail",
    [
        ("roost", ["--plain"]),
        ("quill", ["--plain", "list"]),
        ("blaze", ["--plain", "list"]),
        ("clutch", ["--plain"]),
    ],
)
def test_main_without_argv_reads_sys_argv(name, tail, ws, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["bughunt", *tail])
    assert MODULE_OBJECTS[name].main() == 0
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_main_without_argv_really_parses_sys_argv(name, ws, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["bughunt", "--no-such-flag"])
    with pytest.raises(SystemExit) as stop:
        MODULE_OBJECTS[name].main()
    assert stop.value.code == 2


PARSER_FACTS = {
    "roost": (
        "bughunt roost",
        "Show scope, counts, and URL hosts that fall outside scope.",
    ),
    "quill": (
        "bughunt quill",
        "Write dated engagement notes alongside the captured evidence.",
    ),
    "blaze": ("bughunt blaze", "Attach a workspace label to an existing URL entry."),
    "diff": (
        "bughunt diff",
        "Contrast response evidence from local files or two permitted URLs.",
    ),
    "clutch": (
        "bughunt clutch",
        "Browse captured requests with authentication values concealed.",
    ),
}


@pytest.mark.parametrize("name", sorted(PARSER_FACTS))
def test_parser_prog_and_description(name):
    parser = MODULE_OBJECTS[name].build_parser()
    assert (parser.prog, parser.description) == PARSER_FACTS[name]


# (name, dest, flags, kind, required, help, choices, subcommand, repeatable, store_false, default)
PLAIN_ROW = (
    "PLAIN",
    "plain",
    ("--plain",),
    "bool",
    False,
    "Skip the banner.",
    (),
    "",
    False,
    False,
    "",
)
COMMAND_ROW = (
    "COMMAND",
    "command",
    (),
    "positional",
    False,
    "Subcommand.",
    ("list", "add", "clear"),
    "",
    False,
    False,
    "",
)
SPEC_FACTS = {
    "roost": ((), "", [PLAIN_ROW]),
    "quill": (
        (
            ("list", "Print the pad."),
            ("add", "Append one note."),
            ("clear", "Remove the pad."),
        ),
        "COMMAND",
        [
            PLAIN_ROW,
            (
                "TEXT",
                "text",
                (),
                "positional",
                True,
                "The note. One line.",
                (),
                "add",
                True,
                False,
                "",
            ),
            COMMAND_ROW,
        ],
    ),
    "blaze": (
        (
            ("list", "Print marks, or the URLs for one label."),
            ("add", "Mark one listed URL."),
            ("remove", "Remove one mark."),
        ),
        "COMMAND",
        [
            PLAIN_ROW,
            (
                "LABEL",
                "label",
                (),
                "positional",
                False,
                "Only this label.",
                (),
                "list",
                False,
                False,
                "",
            ),
            (
                "LABEL",
                "label",
                (),
                "positional",
                True,
                "Short label, such as login or review.",
                (),
                "add",
                False,
                False,
                "",
            ),
            (
                "URL",
                "url",
                (),
                "positional",
                True,
                "URL that is already in the shared list.",
                (),
                "add",
                False,
                False,
                "",
            ),
            (
                "LABEL",
                "label",
                (),
                "positional",
                True,
                "",
                (),
                "remove",
                False,
                False,
                "",
            ),
            ("URL", "url", (), "positional", True, "", (), "remove", False, False, ""),
            (
                "COMMAND",
                "command",
                (),
                "positional",
                False,
                "Subcommand.",
                ("list", "add", "remove"),
                "",
                False,
                False,
                "",
            ),
        ],
    ),
    "diff": (
        (),
        "",
        [
            (
                "LEFT",
                "left",
                (),
                "positional",
                True,
                "Response file, a name in responses/, or an http(s) URL.",
                (),
                "",
                False,
                False,
                "",
            ),
            (
                "RIGHT",
                "right",
                (),
                "positional",
                True,
                "Response file, a name in responses/, or an http(s) URL.",
                (),
                "",
                False,
                False,
                "",
            ),
            (
                "TIMEOUT",
                "timeout",
                ("--timeout",),
                "value",
                False,
                "Seconds for each fetch. Default 10.",
                (),
                "",
                False,
                False,
                "10.0",
            ),
            (
                "INSECURE",
                "insecure",
                ("--insecure",),
                "bool",
                False,
                "Do not verify TLS certificates.",
                (),
                "",
                False,
                False,
                "",
            ),
            (
                "COOKIE",
                "cookie",
                ("--cookie",),
                "value",
                False,
                "Cookie for this run. Replaces the saved session cookie.",
                (),
                "",
                False,
                False,
                "",
            ),
            (
                "AUTHORIZATION",
                "authorization",
                ("--authorization",),
                "value",
                False,
                "Authorization for this run. Replaces the saved session value.",
                (),
                "",
                False,
                False,
                "",
            ),
        ],
    ),
    "clutch": (
        (
            ("list", "List saved requests."),
            ("show", "Print one saved request with secrets blanked."),
        ),
        "COMMAND",
        [
            PLAIN_ROW,
            (
                "NAME",
                "name",
                (),
                "positional",
                True,
                "File name inside the requests directory.",
                (),
                "show",
                False,
                False,
                "",
            ),
            (
                "COMMAND",
                "command",
                (),
                "positional",
                False,
                "Subcommand.",
                ("list", "show"),
                "",
                False,
                False,
                "",
            ),
        ],
    ),
}


@pytest.mark.parametrize("name", sorted(SPEC_FACTS))
def test_option_form_the_console_and_catalog_derive_from_the_parser(name):
    subcommands, command_name, rows = SPEC_FACTS[name]
    spec = options.spec_from_parser(MODULE_OBJECTS[name].build_parser())
    assert spec.subcommands == subcommands
    assert spec.command_name == command_name
    assert [tuple(row) for row in spec.options] == rows


def test_parsed_namespaces():
    parse = {
        name: MODULE_OBJECTS[name].build_parser().parse_args for name in MODULE_OBJECTS
    }
    assert vars(parse["roost"]([])) == {"plain": False}
    assert vars(parse["roost"](["--plain"])) == {"plain": True}
    assert vars(parse["quill"](["--plain", "add", "a", "b"])) == {
        "plain": True,
        "command": "add",
        "text": ["a", "b"],
    }
    assert vars(parse["quill"]([])) == {"plain": False, "command": None}
    assert vars(parse["quill"](["list"])) == {"plain": False, "command": "list"}
    assert vars(parse["quill"](["clear"])) == {"plain": False, "command": "clear"}
    assert vars(parse["blaze"](["add", "l", "u"])) == {
        "plain": False,
        "command": "add",
        "label": "l",
        "url": "u",
    }
    assert vars(parse["blaze"](["remove", "l", "u"])) == {
        "plain": False,
        "command": "remove",
        "label": "l",
        "url": "u",
    }
    assert vars(parse["blaze"](["list"])) == {
        "plain": False,
        "command": "list",
        "label": None,
    }
    assert vars(parse["blaze"](["list", "x"])) == {
        "plain": False,
        "command": "list",
        "label": "x",
    }
    assert vars(parse["clutch"](["show", "n"])) == {
        "plain": False,
        "command": "show",
        "name": "n",
    }
    assert vars(parse["clutch"]([])) == {"plain": False, "command": None}
    assert vars(parse["diff"](["a", "b"])) == {
        "left": "a",
        "right": "b",
        "timeout": 10.0,
        "insecure": False,
        "cookie": None,
        "authorization": None,
    }
    full = vars(
        parse["diff"](
            [
                "--timeout",
                "2",
                "--insecure",
                "--cookie",
                "c=1",
                "--authorization",
                "t",
                "a",
                "b",
            ]
        )
    )
    assert full == {
        "left": "a",
        "right": "b",
        "timeout": 2.0,
        "insecure": True,
        "cookie": "c=1",
        "authorization": "t",
    }


@pytest.mark.parametrize(
    "name,argv",
    [
        ("roost", ["--zzz"]),
        ("roost", ["extra"]),
        ("quill", ["--plain", "zzz"]),
        ("quill", ["add"]),
        ("quill", ["add", "x", "--plain"]),
        ("blaze", ["add", "only-label"]),
        ("blaze", ["zzz"]),
        ("clutch", ["show"]),
        ("clutch", ["zzz"]),
        ("diff", ["only-one"]),
        ("diff", ["--timeout", "x", "a", "b"]),
    ],
)
def test_usage_errors_exit_two_before_touching_the_workspace(name, argv, ws, capsys):
    code, out, err = call(capsys, MODULE_OBJECTS[name], *argv)
    assert code == 2 and out == ""
    assert not ws.exists()


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_help_exits_zero_without_a_banner(name, ws, tty):
    out, err = tty()
    with pytest.raises(SystemExit) as stop:
        MODULE_OBJECTS[name].main(["--help"])
    assert stop.value.code == 0
    assert err.getvalue() == "" and "\x1b" not in out.getvalue()


def test_the_console_loader_runs_each_module_by_name(ws, capsys):
    tool_file = Path(scanner.__file__)

    def run(name, *argv):
        capsys.readouterr()
        code = loader.run_named(name, list(argv), tool_file=tool_file, scan_main=None)
        out, err = capsys.readouterr()
        return code, out, err

    code, out, _ = run("quill", "add", "from the loader")
    assert code == 0 and out.endswith("  from the loader\n")
    code, out, _ = run("quill", "list")
    assert code == 0 and out.endswith("  from the loader\n")
    assert run("roost")[:2] == (
        0,
        "scope\n  no scope file\nurls\t0\nrequests\t0\nruns\t0\n"
        "session\tcookie empty, authorization empty\noutside\n  none\n",
    )
    assert run("blaze", "list") == (0, "", "no marks\n")
    assert run("clutch")[0] == 0
    assert run("diff", "left-missing", "right-missing") == (
        2,
        "",
        "No file named left-missing.\n",
    )


# --------------------------------------------------------------------------------------------
# banner and colour layer shared by roost, quill, blaze, clutch
# --------------------------------------------------------------------------------------------

ROOST_BANNER_PLAIN = (
    "            ___\n",
    "         .-'   `-.\n",
    "        /   roost  \\\n",
    "        |  (o) (o) |\n",
    "         \\    ^    /\n",
    "          '-----'\n",
    "         ===[ ]===\n",
    "the perch above this engagement",
)

ROOST_BANNER_COLOR = (
    "\x1b[1;96m            ___\x1b[0m\n",
    "\x1b[1;96m         .-'   `-.\x1b[0m\n",
    "\x1b[1;96m        /   \x1b[1;95mroost\x1b[1;96m  \\\x1b[0m\n",
    "\x1b[1;96m        |  \x1b[1;93m(\x1b[1;96mo\x1b[1;93m)\x1b[1;96m \x1b[1;93m(\x1b[1;96mo\x1b[1;93m)\x1b[1;96m |\x1b[0m\n",
    "\x1b[1;96m         \\    ^    /\x1b[0m\n",
    "\x1b[1;96m          '-----'\x1b[0m\n",
    "\x1b[1;96m         ===\x1b[1;93m[\x1b[1;96m \x1b[1;93m]\x1b[1;96m===\x1b[0m\n",
    "\x1b[2;96mthe perch above this engagement\x1b[0m",
)

QUILL_BANNER_PLAIN = (
    "               /\n",
    "              /\n",
    "             /\n",
    "            / \\\n",
    "           | quill |\n",
    "            \\   /\n",
    "             [_]\n",
    "field notes beside the scope",
)

QUILL_BANNER_COLOR = (
    "\x1b[1;96m               /\x1b[0m\n",
    "\x1b[1;96m              /\x1b[0m\n",
    "\x1b[1;96m             /\x1b[0m\n",
    "\x1b[1;96m            / \\\x1b[0m\n",
    "\x1b[1;96m           | \x1b[1;95mquill\x1b[1;96m |\x1b[0m\n",
    "\x1b[1;96m            \\   /\x1b[0m\n",
    "\x1b[1;96m             \x1b[1;93m[\x1b[1;96m_\x1b[1;93m]\x1b[1;96m\x1b[0m\n",
    "\x1b[2;96mfield notes beside the scope\x1b[0m",
)

BLAZE_BANNER_PLAIN = (
    "              )\n",
    "             ) \\\n",
    "            )   )\n",
    "           ( blaze )\n",
    "            )   )\n",
    "             ) /\n",
    "             [_]\n",
    "trail marks on the url list",
)

BLAZE_BANNER_COLOR = (
    "\x1b[1;96m              \x1b[1;93m)\x1b[1;96m\x1b[0m\n",
    "\x1b[1;96m             \x1b[1;93m)\x1b[1;96m \\\x1b[0m\n",
    "\x1b[1;96m            \x1b[1;93m)\x1b[1;96m   \x1b[1;93m)\x1b[1;96m\x1b[0m\n",
    "\x1b[1;96m           ( \x1b[1;95mblaze\x1b[1;96m )\x1b[0m\n",
    "\x1b[1;96m            \x1b[1;93m)\x1b[1;96m   \x1b[1;93m)\x1b[1;96m\x1b[0m\n",
    "\x1b[1;96m             \x1b[1;93m)\x1b[1;96m /\x1b[0m\n",
    "\x1b[1;96m             \x1b[1;93m[\x1b[1;96m_\x1b[1;93m]\x1b[1;96m\x1b[0m\n",
    "\x1b[2;96mtrail marks on the url list\x1b[0m",
)

CLUTCH_BANNER_PLAIN = (
    "            \\\\   //\n",
    "             \\\\ //\n",
    "              \\V/\n",
    "          .--------.\n",
    "          | clutch |\n",
    "          '--------'\n",
    "            [held]\n",
    "requests held in the talons",
)

CLUTCH_BANNER_COLOR = (
    "\x1b[1;96m            \\\\   //\x1b[0m\n",
    "\x1b[1;96m             \\\\ //\x1b[0m\n",
    "\x1b[1;96m              \\V/\x1b[0m\n",
    "\x1b[1;96m          .--------.\x1b[0m\n",
    "\x1b[1;96m          | \x1b[1;95mclutch\x1b[1;96m |\x1b[0m\n",
    "\x1b[1;96m          '--------'\x1b[0m\n",
    "\x1b[1;96m            \x1b[1;93m[\x1b[1;96mheld\x1b[1;93m]\x1b[1;96m\x1b[0m\n",
    "\x1b[2;96mrequests held in the talons\x1b[0m",
)

BANNERS = {
    "roost": ("".join(ROOST_BANNER_PLAIN), "".join(ROOST_BANNER_COLOR)),
    "quill": ("".join(QUILL_BANNER_PLAIN), "".join(QUILL_BANNER_COLOR)),
    "blaze": ("".join(BLAZE_BANNER_PLAIN), "".join(BLAZE_BANNER_COLOR)),
    "clutch": ("".join(CLUTCH_BANNER_PLAIN), "".join(CLUTCH_BANNER_COLOR)),
}
HARMLESS_ARGV = {"roost": [], "quill": ["list"], "blaze": ["list"], "clutch": []}


@pytest.mark.parametrize("name", sorted(BANNERS))
def test_format_banner_bytes(name):
    plain, colored = BANNERS[name]
    module = MODULE_OBJECTS[name]
    assert module.format_banner(False) == plain
    assert module.format_banner(True) == colored


@pytest.mark.parametrize("name", sorted(BANNERS))
def test_banner_goes_to_stderr_only_when_stderr_is_a_terminal(name, ws, capsys):
    code, out, err = call(capsys, MODULE_OBJECTS[name], *HARMLESS_ARGV[name])
    assert code == 0
    assert BANNERS[name][0] not in err and "\x1b" not in err + out


@pytest.mark.parametrize("name", sorted(BANNERS))
def test_terminal_run_prints_the_coloured_banner_then_a_blank_line_on_stderr(
    name, ws, tty
):
    out, err = tty()
    assert MODULE_OBJECTS[name].main(HARMLESS_ARGV[name]) == 0
    assert err.getvalue().startswith(BANNERS[name][1] + "\n\n")


@pytest.mark.parametrize("name", sorted(BANNERS))
def test_plain_flag_skips_the_banner_and_the_colour(name, ws, tty):
    out, err = tty()
    assert MODULE_OBJECTS[name].main(["--plain", *HARMLESS_ARGV[name]]) == 0
    assert (
        BANNERS[name][0] not in err.getvalue()
        and "\x1b" not in err.getvalue() + out.getvalue()
    )


@pytest.mark.parametrize("name", sorted(BANNERS))
@pytest.mark.parametrize("setting", [("TERM", "dumb"), ("TERM", ""), ("NO_COLOR", "1")])
def test_a_terminal_without_colour_gets_the_plain_banner(
    name, setting, ws, tty, monkeypatch
):
    out, err = tty()
    monkeypatch.setenv(*setting)
    assert MODULE_OBJECTS[name].main(HARMLESS_ARGV[name]) == 0
    assert err.getvalue().startswith(BANNERS[name][0] + "\n\n")
    assert "\x1b" not in err.getvalue() + out.getvalue()


def test_an_empty_no_color_variable_does_not_disable_colour(ws, tty, monkeypatch):
    out, err = tty()
    monkeypatch.setenv("NO_COLOR", "")
    roost.main([])
    assert err.getvalue().startswith(BANNERS["roost"][1])
    assert MAGENTA in out.getvalue()


def test_a_missing_term_variable_disables_colour(ws, tty, monkeypatch):
    out, err = tty()
    monkeypatch.delenv("TERM", raising=False)
    roost.main([])
    assert err.getvalue().startswith(BANNERS["roost"][0] + "\n\n")
    assert "\x1b" not in out.getvalue()


def test_stdout_colour_follows_stdout_not_stderr(ws, monkeypatch, capsys):
    colored_err = _Tty()
    monkeypatch.setattr(sys, "stderr", colored_err)
    monkeypatch.setenv("TERM", "xterm")
    quill.main(["list"])
    assert colored_err.getvalue().startswith(BANNERS["quill"][1])
    colored_out = _Tty()
    monkeypatch.setattr(sys, "stdout", colored_out)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    put(ws / "notes.txt", "2026-01-02 03:04:05Z a note\n")
    quill.main(["list"])
    assert (
        colored_out.getvalue()
        == f"  {DIM}2026-01-02 03:04:05Z{RESET}  {WHITE}a note{RESET}\n"
    )


@pytest.mark.parametrize(
    "name,argv",
    [
        ("roost", ["--plain"]),
        ("quill", ["--plain", "add", "note"]),
        ("quill", ["--plain", "list"]),
        ("quill", ["--plain", "clear"]),
        ("blaze", ["--plain", "list"]),
        ("blaze", ["--plain", "remove", "a", "b"]),
        ("clutch", ["--plain"]),
        ("clutch", ["--plain", "show", "x.http"]),
    ],
)
def test_these_modules_never_reach_a_socket(name, argv, ws, no_network, capsys):
    call(capsys, MODULE_OBJECTS[name], *argv)


# --------------------------------------------------------------------------------------------
# roost
# --------------------------------------------------------------------------------------------

ROOST_SCOPE = "# engagement\nexample.com\n*.cdn.test\n10.0.0.0/8\n"
ROOST_URLS = (
    "# harvested\n"
    "https://example.com/a\n"
    "https://www.example.com/b\n"
    "https://evil.test/x\n"
    "\n"
    "https://Evil.Test./y\n"
    "http://10.1.2.3/z\n"
    "http://192.168.0.1/q\n"
    "http://localhost:8080/\n"
    "https://aaa.cdn.test/\n"
    "https://zzz.out.test\n"
    "https://aaa.out.test\n"
)


def test_report_is_a_frozen_dataclass_with_this_field_order():
    assert [field.name for field in dataclasses.fields(roost.Report)] == [
        "entries",
        "urls",
        "requests",
        "runs",
        "cookie",
        "authorization",
        "outside",
    ]
    assert roost.Report.__dataclass_params__.frozen is True
    report = roost.Report(("a",), 1, 2, 3, True, False, ("b",))
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.urls = 5
    assert report == roost.Report(("a",), 1, 2, 3, True, False, ("b",))


def test_gather_on_an_empty_workspace(ws):
    assert roost.gather() == roost.Report(None, 0, 0, 0, False, False, ())


def test_gather_counts_entries_urls_requests_and_sorts_the_outside_hosts(ws):
    put(ws / "scope.txt", ROOST_SCOPE)
    put(ws / "urls.txt", ROOST_URLS)
    put(ws / "requests" / "a.http", b"GET / HTTP/1.1\r\n\r\n")
    put(ws / "requests" / "b.http", b"x")
    (ws / "requests" / "nested").mkdir()
    put(ws / "requests" / "nested" / "deep.http", b"x")
    report = roost.gather()
    assert report.entries == ("example.com", "*.cdn.test", "10.0.0.0/8")
    assert report.urls == 10
    assert report.requests == 2
    assert report.outside == (
        "192.168.0.1",
        "aaa.out.test",
        "evil.test",
        "zzz.out.test",
    )


def test_gather_counts_ledger_runs_separately_from_saved_request_files(policy):
    """Verification and other runs land in runs/, not requests/; roost must surface them too (BH-20)."""
    _document, workspace = policy
    put(workspace / "requests" / "a.http", b"GET / HTTP/1.1\r\n\r\n")
    for _ in range(2):
        ledger.begin(
            egress.current_profile(),
            tool="fixture",
            operation="manual",
            target="https://allowed.example/",
            request=b"GET / HTTP/1.1\r\n\r\n",
        ).finish()
    report = roost.gather()
    assert report.requests == 1
    assert report.runs == 2


def test_without_a_scope_file_every_non_loopback_url_host_is_outside(ws):
    put(
        ws / "urls.txt",
        "https://example.com/a\nhttp://localhost/x\nhttp://127.0.0.1:9/y\n",
    )
    report = roost.gather()
    assert report.entries is None
    assert report.urls == 3
    assert report.outside == ("example.com",)


def test_a_scope_file_with_only_comments_is_active_but_empty(ws):
    put(ws / "scope.txt", "# nothing yet\n")
    put(ws / "urls.txt", "https://example.com/a\n")
    report = roost.gather()
    assert report.entries == ()
    assert report.outside == ("example.com",)


def test_session_flags_come_from_the_saved_credentials_and_values_stay_hidden(
    ws, capsys
):
    session.write_session({"cookie": "sekrit-cookie", "authorization": ""})
    assert (roost.gather().cookie, roost.gather().authorization) == (True, False)
    session.write_session(
        {"cookie": "sekrit-cookie", "authorization": "Bearer sekrit-token"}
    )
    assert (roost.gather().cookie, roost.gather().authorization) == (True, True)
    code, out, err = call(capsys, roost, "--plain")
    assert code == 0 and "session\tcookie saved, authorization saved\n" in out
    assert "sekrit" not in out + err


def test_a_selected_named_actor_supplies_the_credential_flags(ws):
    session.write_session({"cookie": "legacy-cookie", "authorization": "legacy-token"})
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.set_credential("owner", "cookie", "c=1")
    identity.use_profile("owner")
    report = roost.gather()
    assert (report.cookie, report.authorization) == (True, False)


def test_defect_a_corrupt_selected_actor_should_not_crash_the_status_view(ws, capsys):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.use_profile("owner")
    put(ws / "identities" / "owner.json", "{not json")
    assert roost.main(["--plain"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip()


def test_format_report_plain_variants():
    assert roost.format_report(
        roost.Report(None, 0, 0, 0, False, False, ()), False
    ) == (
        "scope\n  no scope file\nurls\t0\nrequests\t0\nruns\t0\nsession\tcookie empty, authorization empty\n"
        "outside\n  none\n"
    )
    assert roost.format_report(roost.Report((), 1, 2, 5, False, True, ()), False) == (
        "scope\n  no entries\nurls\t1\nrequests\t2\nruns\t5\nsession\tcookie empty, authorization saved\n"
        "outside\n  none\n"
    )
    assert roost.format_report(
        roost.Report(
            ("a.test", "*.b.test"), 3, 4, 7, True, False, ("x.test", "y.test")
        ),
        False,
    ) == (
        "scope\n  a.test\n  *.b.test\nurls\t3\nrequests\t4\nruns\t7\nsession\tcookie saved, authorization empty\n"
        "outside\n  x.test\n  y.test\n"
    )


def test_format_report_colour_variants():
    populated = roost.Report(("a.test",), 3, 2, 9, True, False, ("x.test",))
    assert roost.format_report(populated, True) == (
        f"{MAGENTA}scope{RESET}\n  {WHITE}a.test{RESET}\n"
        f"  {CYAN}urls        {RESET} {WHITE}3{RESET}\n"
        f"  {CYAN}requests    {RESET} {WHITE}2{RESET}\n"
        f"  {CYAN}runs        {RESET} {WHITE}9{RESET}\n"
        f"  {CYAN}session     {RESET} {WHITE}cookie saved, authorization empty{RESET}\n"
        f"{MAGENTA}outside{RESET}\n  {YELLOW}x.test{RESET}\n"
    )
    inactive = roost.Report(None, 0, 0, 0, False, False, ())
    assert roost.format_report(inactive, True) == (
        f"{MAGENTA}scope{RESET}\n  {YELLOW}no scope file{RESET}\n"
        f"  {CYAN}urls        {RESET} {WHITE}0{RESET}\n"
        f"  {CYAN}requests    {RESET} {WHITE}0{RESET}\n"
        f"  {CYAN}runs        {RESET} {WHITE}0{RESET}\n"
        f"  {CYAN}session     {RESET} {WHITE}cookie empty, authorization empty{RESET}\n"
        f"{MAGENTA}outside{RESET}\n  {WHITE}none{RESET}\n"
    )
    empty = roost.Report((), 0, 0, 0, False, False, ())
    assert roost.format_report(empty, True).startswith(
        f"{MAGENTA}scope{RESET}\n  {WHITE}no entries{RESET}\n"
    )


def test_main_prints_the_full_report_and_returns_zero(ws, capsys):
    put(ws / "scope.txt", ROOST_SCOPE)
    put(ws / "urls.txt", ROOST_URLS)
    code, out, err = call(capsys, roost, "--plain")
    assert (code, err) == (0, "")
    assert out == (
        "scope\n  example.com\n  *.cdn.test\n  10.0.0.0/8\n"
        "urls\t10\nrequests\t0\nruns\t0\nsession\tcookie empty, authorization empty\n"
        "outside\n  192.168.0.1\n  aaa.out.test\n  evil.test\n  zzz.out.test\n"
    )
    assert roost.main([]) == 0


def test_main_colours_the_report_on_a_colour_terminal(ws, tty):
    out, err = tty()
    put(ws / "scope.txt", "example.com\n")
    put(ws / "urls.txt", "https://example.com/a\nhttps://evil.test/b\n")
    roost.main([])
    assert out.getvalue() == roost.format_report(roost.gather(), True)
    assert out.getvalue().startswith(f"{MAGENTA}scope{RESET}")


def test_roost_never_writes_to_the_workspace(ws):
    put(ws / "scope.txt", "example.com\n")
    before = sorted(p.name for p in ws.iterdir())
    roost.main(["--plain"])
    assert sorted(p.name for p in ws.iterdir()) == before


# --------------------------------------------------------------------------------------------
# quill
# --------------------------------------------------------------------------------------------


def test_notes_path_is_notes_txt_in_the_current_workspace(ws, monkeypatch, tmp_path):
    assert quill.notes_path() == ws / "notes.txt"
    other = tmp_path / "elsewhere"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(other))
    assert quill.notes_path() == other / "notes.txt"


def test_add_writes_a_utc_stamped_line_and_echoes_it(ws, capsys):
    before = datetime.now(timezone.utc).replace(microsecond=0)
    code, out, err = call(capsys, quill, "--plain", "add", "hello", "world")
    after = datetime.now(timezone.utc)
    assert (code, err) == (0, "")
    match = re.fullmatch(rf"({STAMP_PATTERN})  hello world\n", out)
    assert match, out
    assert before <= utc_stamp(match.group(1)) <= after
    assert on_disk(ws / "notes.txt") == f"{NOTES_HEADER}{match.group(1)} hello world\n"


def test_add_does_not_create_a_scope_file_but_does_create_the_workspace(ws, capsys):
    assert not ws.exists()
    quill.main(["--plain", "add", "x"])
    assert (ws / "notes.txt").is_file() and not (ws / "scope.txt").exists()
    assert not workspace.scope_is_active()


def test_add_collapses_whitespace_inside_the_note(ws, capsys):
    code, out, err = call(capsys, quill, "--plain", "add", "a   b\tc", "  d ")
    assert code == 0
    assert out.endswith("  a b c d\n")
    assert quill.read_notes()[0][1] == "a b c d"


@pytest.mark.parametrize(
    "argv", [[""], ["   "], ["a\nb"], ["a", "b\r"], ["line one\r\nline two"], ["\n"]]
)
def test_add_refuses_empty_or_multi_line_text(argv, ws, capsys):
    code, out, err = call(capsys, quill, "--plain", "add", *argv)
    assert (code, out, err) == (2, "", "Give a single line.\n")
    assert not (ws / "notes.txt").exists()


def test_add_collapses_unicode_whitespace_that_is_not_a_cr_or_lf(ws, capsys):
    code, out, err = call(capsys, quill, "--plain", "add", "a b\x0bc d")
    assert code == 0 and out.endswith("  a b c d\n")


def test_add_appends_after_existing_notes_and_keeps_their_stamps(ws, capsys):
    put(
        ws / "notes.txt",
        f"{NOTES_HEADER}2026-01-02 03:04:05Z first\n2026-01-02 03:04:06Z second\n",
    )
    quill.main(["--plain", "add", "third"])
    rows = quill.read_notes()
    assert rows[:2] == [
        ("2026-01-02 03:04:05Z", "first"),
        ("2026-01-02 03:04:06Z", "second"),
    ]
    assert len(rows) == 3 and rows[2][1] == "third"
    assert on_disk(ws / "notes.txt").startswith(
        f"{NOTES_HEADER}2026-01-02 03:04:05Z first\n2026-01-02 03:04:06Z second\n"
    )


def test_unicode_notes_round_trip_as_utf8(ws, capsys):
    quill.main(["--plain", "add", "café ✓ 日本"])
    assert "café ✓ 日本" in (ws / "notes.txt").read_bytes().decode("utf-8")
    assert quill.read_notes()[0][1] == "café ✓ 日本"


def test_list_prints_every_note_in_file_order(ws, capsys):
    put(
        ws / "notes.txt",
        f"{NOTES_HEADER}2026-01-02 03:04:05Z first\n2026-01-02 03:04:06Z second\n",
    )
    for argv in (["--plain", "list"], ["--plain"], ["list"]):
        code, out, err = call(capsys, quill, *argv)
        assert (code, err) == (0, "")
        assert out == "2026-01-02 03:04:05Z  first\n2026-01-02 03:04:06Z  second\n"


def test_list_with_no_notes_says_so_on_stderr(ws, capsys):
    assert call(capsys, quill, "--plain", "list") == (0, "", "no notes\n")
    assert call(capsys, quill, "--plain") == (0, "", "no notes\n")


def test_clear_removes_the_pad_and_always_confirms_on_stdout(ws, capsys):
    put(ws / "notes.txt", f"{NOTES_HEADER}2026-01-02 03:04:05Z first\n")
    assert call(capsys, quill, "--plain", "clear") == (0, "notes cleared\n", "")
    assert not (ws / "notes.txt").exists()
    assert call(capsys, quill, "--plain", "clear") == (0, "notes cleared\n", "")


RAW_NOTES = (
    b"# a comment\n"
    b"\n"
    b"2026-01-02 03:04:05Z first note\n"
    b"  2026-01-02 03:04:06Z   padded text  \n"
    b"short line\n"
    b"2026-01-02 03:04:07Z\n"
    b"2026-01-02 03:04:08Z x\n"
    b"2026-01-02 03:04:09Zx glued\n"
    b"2026-01-02T03:04:10Z not validated\n"
    b"# 2026-01-02 03:04:11Z commented out\n"
    b"2026-01-02 03:04:12Z caf\xe9 bytes\n"
)


def test_read_notes_parsing_rules(ws):
    put(ws / "notes.txt", RAW_NOTES)
    assert quill.read_notes() == [
        ("2026-01-02 03:04:05Z", "first note"),
        ("2026-01-02 03:04:06Z", "  padded text"),
        ("2026-01-02 03:04:08Z", "x"),
        ("2026-01-02T03:04:10Z", "not validated"),
        ("2026-01-02 03:04:12Z", "caf� bytes"),
    ]


def test_read_notes_without_a_file_is_empty(ws):
    assert quill.read_notes() == []
    (ws / "notes.txt").mkdir(parents=True)
    assert quill.read_notes() == []


def test_format_note_plain_and_colour():
    assert (
        quill.format_note("2026-01-02 03:04:05Z", "txt", False)
        == "2026-01-02 03:04:05Z  txt"
    )
    assert quill.format_note("2026-01-02 03:04:05Z", "txt", True) == (
        f"  {DIM}2026-01-02 03:04:05Z{RESET}  {WHITE}txt{RESET}"
    )


def test_quill_add_preserves_existing_lines(
    ws,
):
    put(
        ws / "notes.txt",
        "# my own header\n\n2026-01-02 03:04:05Z kept\nfree text a person typed\n",
    )
    quill.main(["--plain", "add", "new"])
    text = on_disk(ws / "notes.txt")
    assert text.startswith(
        "# my own header\n\n2026-01-02 03:04:05Z kept\nfree text a person typed\n"
    )


def test_defect_add_should_keep_lines_it_does_not_understand(ws):
    put(
        ws / "notes.txt",
        "# my own header\n\n2026-01-02 03:04:05Z kept\nfree text a person typed\n",
    )
    quill.main(["--plain", "add", "new"])
    assert "free text a person typed" in on_disk(ws / "notes.txt")


def test_quill_add_preserves_original_bytes_and_separates_unterminated_notes(ws):
    original = b"# custom\r\n\xff free text"
    put(ws / "notes.txt", original)
    assert quill.main(["--plain", "add", "new"]) == 0
    assert (ws / "notes.txt").read_bytes().startswith(original + b"\n")


def test_defect_note_text_should_not_carry_raw_escape_sequences_to_the_terminal(
    ws, capsys
):
    put(ws / "notes.txt", "2026-01-02 03:04:05Z \x1b[2Jcleared\n")
    code, out, err = call(capsys, quill, "--plain", "list")
    assert "\x1b" not in out


# --------------------------------------------------------------------------------------------
# blaze
# --------------------------------------------------------------------------------------------

LISTED_URLS = "# comment\nhttps://a.test/login\n  https://a.test/x  \n\nhttps://b.test/y\n# https://hidden.test/z\n"


@pytest.fixture
def listed(ws):
    put(ws / "urls.txt", LISTED_URLS)
    return ws


def test_marks_path_is_marks_txt_in_the_current_workspace(ws):
    assert blaze.marks_path() == ws / "marks.txt"


def test_add_marks_a_listed_url_and_writes_the_file(listed, capsys):
    code, out, err = call(
        capsys, blaze, "--plain", "add", "login", "https://a.test/login"
    )
    assert (code, out, err) == (0, "login marks https://a.test/login\n", "")
    assert (
        on_disk(listed / "marks.txt") == f"{MARKS_HEADER}login https://a.test/login\n"
    )
    assert not (listed / "scope.txt").exists()


def test_add_normalises_the_label_and_trims_the_url(listed, capsys):
    code, out, err = call(
        capsys, blaze, "--plain", "add", " LoGiN ", "  https://a.test/x "
    )
    assert (code, out, err) == (0, "login marks https://a.test/x\n", "")
    assert blaze.read_marks() == [("login", "https://a.test/x")]


def test_add_trims_a_trailing_newline_from_the_url_before_checking_it(listed, capsys):
    code, out, err = call(
        capsys, blaze, "--plain", "add", "login", "https://a.test/login\r\n"
    )
    assert (code, out, err) == (0, "login marks https://a.test/login\n", "")


def test_add_keeps_marks_in_insertion_order_and_allows_shared_labels_and_urls(
    listed, capsys
):
    for label, url in (
        ("login", "https://a.test/login"),
        ("review", "https://b.test/y"),
        ("login", "https://b.test/y"),
        ("zeta", "https://a.test/login"),
    ):
        assert blaze.main(["--plain", "add", label, url]) == 0
    assert blaze.read_marks() == [
        ("login", "https://a.test/login"),
        ("review", "https://b.test/y"),
        ("login", "https://b.test/y"),
        ("zeta", "https://a.test/login"),
    ]


def test_adding_an_existing_mark_is_a_no_op_that_succeeds(listed, capsys):
    blaze.main(["--plain", "add", "login", "https://a.test/login"])
    before = (listed / "marks.txt").read_bytes()
    code, out, err = call(
        capsys, blaze, "--plain", "add", "LOGIN", "https://a.test/login"
    )
    assert (code, out, err) == (0, "login already marks https://a.test/login\n", "")
    assert (listed / "marks.txt").read_bytes() == before


@pytest.mark.parametrize(
    "url",
    [
        "https://not-listed.test/",
        "https://hidden.test/z",
        "# https://hidden.test/z",
        "https://a.test/login/",
    ],
)
def test_add_refuses_a_url_that_is_not_in_the_shared_list(url, listed, capsys):
    code, out, err = call(capsys, blaze, "--plain", "add", "login", url)
    assert (code, out, err) == (2, "", "That URL is not in the shared list.\n")
    assert not (listed / "marks.txt").exists()


def test_add_with_no_url_list_at_all_is_refused(ws, capsys):
    assert call(capsys, blaze, "--plain", "add", "login", "https://a.test/login") == (
        2,
        "",
        "That URL is not in the shared list.\n",
    )
    assert not ws.exists()


@pytest.mark.parametrize(
    "url", ["", "   ", "https://a.test/login\nx", "https://a.test/login\rx"]
)
def test_add_refuses_an_empty_or_multi_line_url(url, listed, capsys):
    assert call(capsys, blaze, "--plain", "add", "login", url) == (
        2,
        "",
        "Give a single URL.\n",
    )


LABEL_MESSAGE = "A label is a short word, such as login.\n"


@pytest.mark.parametrize(
    "label", ["", "  ", "_x", "a b", "a.b", "a/b", "x" * 33, "café", "a\nb"]
)
def test_add_refuses_a_bad_label(label, listed, capsys):
    assert call(capsys, blaze, "--plain", "add", label, "https://a.test/login") == (
        2,
        "",
        LABEL_MESSAGE,
    )


@pytest.mark.parametrize(
    "label,stored",
    [
        ("a", "a"),
        ("0x", "0x"),
        ("a-b_c", "a-b_c"),
        ("x" * 32, "x" * 32),
        ("MiXeD", "mixed"),
        ("9lives", "9lives"),
    ],
)
def test_add_accepts_a_well_formed_label(label, stored, listed, capsys):
    assert blaze.main(["--plain", "add", label, "https://a.test/login"]) == 0
    assert blaze.read_marks() == [(stored, "https://a.test/login")]


def test_the_label_is_checked_before_the_url(listed, capsys):
    assert call(capsys, blaze, "--plain", "add", "bad label", "") == (
        2,
        "",
        LABEL_MESSAGE,
    )


def test_remove_deletes_one_mark_and_removing_the_last_deletes_the_file(listed, capsys):
    blaze.main(["--plain", "add", "login", "https://a.test/login"])
    blaze.main(["--plain", "add", "review", "https://b.test/y"])
    code, out, err = call(
        capsys, blaze, "--plain", "remove", "LOGIN", "  https://a.test/login "
    )
    assert (code, out, err) == (0, "login cleared https://a.test/login\n", "")
    assert on_disk(listed / "marks.txt") == f"{MARKS_HEADER}review https://b.test/y\n"
    assert (
        call(capsys, blaze, "--plain", "remove", "review", "https://b.test/y")[0] == 0
    )
    assert not (listed / "marks.txt").exists()


def test_remove_does_not_require_the_url_to_still_be_listed(listed, capsys):
    blaze.main(["--plain", "add", "login", "https://a.test/login"])
    (listed / "urls.txt").write_text("", encoding="utf-8")
    assert (
        call(capsys, blaze, "--plain", "remove", "login", "https://a.test/login")[0]
        == 0
    )


def test_remove_of_an_unsaved_mark_fails(listed, capsys):
    blaze.main(["--plain", "add", "login", "https://a.test/login"])
    before = (listed / "marks.txt").read_bytes()
    assert call(capsys, blaze, "--plain", "remove", "login", "https://b.test/y") == (
        2,
        "",
        "That mark is not saved.\n",
    )
    assert call(
        capsys, blaze, "--plain", "remove", "other", "https://a.test/login"
    ) == (2, "", "That mark is not saved.\n")
    assert (listed / "marks.txt").read_bytes() == before


@pytest.mark.parametrize(
    "label,url",
    [
        ("!!", "https://a.test/login"),
        ("login", ""),
        ("login", "   "),
        ("", "https://a.test/login"),
    ],
)
def test_remove_needs_a_valid_label_and_a_url(label, url, listed, capsys):
    assert call(capsys, blaze, "--plain", "remove", label, url) == (
        2,
        "",
        "Give a label and a URL.\n",
    )


def _seed_marks(listed):
    put(
        listed / "marks.txt",
        f"{MARKS_HEADER}login https://a.test/login\nreview https://b.test/y\n"
        "login https://b.test/y\n",
    )


def test_list_without_a_label_prints_headings_per_consecutive_run(listed, capsys):
    _seed_marks(listed)
    expected = "login\n  https://a.test/login\nreview\n  https://b.test/y\nlogin\n  https://b.test/y\n"
    assert call(capsys, blaze, "--plain", "list") == (0, expected, "")
    assert call(capsys, blaze, "--plain") == (0, expected, "")


def test_list_prints_one_heading_for_consecutive_marks_with_the_same_label(
    listed, capsys
):
    put(
        listed / "marks.txt",
        f"{MARKS_HEADER}login https://a.test/login\nlogin https://b.test/y\n"
        "review https://a.test/x\n",
    )
    assert call(capsys, blaze, "--plain", "list") == (
        0,
        "login\n  https://a.test/login\n  https://b.test/y\nreview\n  https://a.test/x\n",
        "",
    )


def test_list_with_an_empty_label_argument_lists_everything(listed, capsys):
    _seed_marks(listed)
    everything = call(capsys, blaze, "--plain", "list")
    assert call(capsys, blaze, "--plain", "list", "") == everything


def test_list_with_a_label_prints_just_its_urls_in_file_order(listed, capsys):
    _seed_marks(listed)
    expected = "https://a.test/login\nhttps://b.test/y\n"
    assert call(capsys, blaze, "--plain", "list", "login") == (0, expected, "")
    assert call(capsys, blaze, "--plain", "list", "LOGIN") == (0, expected, "")


def test_list_reports_missing_marks_on_stderr_with_exit_zero(listed, capsys):
    assert call(capsys, blaze, "--plain", "list") == (0, "", "no marks\n")
    _seed_marks(listed)
    assert call(capsys, blaze, "--plain", "list", "zzz") == (0, "", "no zzz marks\n")


@pytest.mark.parametrize("label", ["bad label!", "_x", "x" * 33])
def test_list_refuses_a_bad_label(label, listed, capsys):
    assert call(capsys, blaze, "--plain", "list", label) == (2, "", LABEL_MESSAGE)


def test_list_colours_headings_and_urls_on_a_terminal_but_not_a_label_listing(
    listed, tty
):
    out, err = tty()
    _seed_marks(listed)
    blaze.main(["list"])
    assert out.getvalue() == (
        f"{MAGENTA}login{RESET}\n  {WHITE}https://a.test/login{RESET}\n"
        f"{MAGENTA}review{RESET}\n  {WHITE}https://b.test/y{RESET}\n"
        f"{MAGENTA}login{RESET}\n  {WHITE}https://b.test/y{RESET}\n"
    )
    out.truncate(0)
    out.seek(0)
    blaze.main(["list", "login"])
    assert out.getvalue() == "https://a.test/login\nhttps://b.test/y\n"


RAW_MARKS = (
    "# a comment\n"
    "Login   https://a.test/login \n"
    "\n"
    "nospace\n"
    "Two https://a.test/x extra words\n"
    " \tTab\thttps://x\n"
    "UPPER\thttps://tab-separated\n"
)


def test_read_marks_parsing_rules(ws):
    put(ws / "marks.txt", RAW_MARKS)
    assert blaze.read_marks() == [
        ("login", "https://a.test/login"),
        ("two", "https://a.test/x extra words"),
    ]


def test_read_marks_without_a_file_is_empty(ws):
    assert blaze.read_marks() == []
    (ws / "marks.txt").mkdir(parents=True)
    assert blaze.read_marks() == []


def test_read_marks_does_not_validate_labels_from_the_file(ws, capsys):
    put(ws / "marks.txt", "_odd https://a.test/\n")
    assert blaze.read_marks() == [("_odd", "https://a.test/")]
    assert call(capsys, blaze, "--plain", "list") == (
        0,
        "_odd\n  https://a.test/\n",
        "",
    )


def test_blaze_a_write_preserves_hand_written_lines(
    listed,
):
    put(listed / "marks.txt", "# my note\nlogin https://a.test/login\nnospaceline\n")
    blaze.main(["--plain", "add", "review", "https://b.test/y"])
    text = on_disk(listed / "marks.txt")
    assert (
        text
        == "# my note\nlogin https://a.test/login\nnospaceline\nreview https://b.test/y\n"
    )


def test_defect_a_write_should_keep_lines_it_does_not_understand(listed):
    put(listed / "marks.txt", "# my note\nlogin https://a.test/login\n")
    blaze.main(["--plain", "add", "review", "https://b.test/y"])
    assert "# my note" in on_disk(listed / "marks.txt")


def test_blaze_add_and_remove_preserve_original_unparsed_bytes(listed):
    untouched = b"# custom \xff\r\nnospaceline\r\n"
    original = untouched + b"LOGIN https://a.test/login"
    put(listed / "marks.txt", original)
    assert blaze.main(["--plain", "add", "review", "https://b.test/y"]) == 0
    assert (listed / "marks.txt").read_bytes().startswith(original + b"\n")
    assert blaze.main(["--plain", "remove", "login", "https://a.test/login"]) == 0
    assert blaze.main(["--plain", "remove", "review", "https://b.test/y"]) == 0
    assert (listed / "marks.txt").read_bytes() == untouched


# --------------------------------------------------------------------------------------------
# diff: saved-file parsing and rendering
# --------------------------------------------------------------------------------------------


def test_side_is_a_dataclass_with_defaults():
    assert [field.name for field in dataclasses.fields(diff_cmd.Side)] == [
        "label",
        "status",
        "headers",
        "body",
        "truncated",
        "body_size",
    ]
    bare = diff_cmd.Side("x", "200")
    assert (bare.headers, bare.body, bare.truncated) == ({}, "", False)
    bare.headers["a"] = "b"
    assert diff_cmd.Side("y", "200").headers == {}
    assert diff_cmd.Side("x", "200", {"a": "1"}, "b", True) == diff_cmd.Side(
        "x", "200", {"a": "1"}, "b", True
    )


PARSE_VECTORS = [
    (
        "no blank line keeps the raw text",
        b"just a body\r\nno blank line",
        ("", {}, "just a body\r\nno blank line", False),
    ),
    ("empty", b"", ("", {}, "", False)),
    (
        "status line",
        b"HTTP/1.1 200 OK\r\nA: 1\r\n\r\nbody",
        ("200", {"a": "1"}, "body", False),
    ),
    (
        "status line, bare LF",
        b"HTTP/1.1 200 OK\nA: 1\n\nbody",
        ("200", {"a": "1"}, "body", False),
    ),
    (
        "crlf body is normalised",
        b"HTTP/1.1 200 OK\r\nA: 1\r\n\r\nbody\r\nmore",
        ("200", {"a": "1"}, "body\nmore", False),
    ),
    (
        "status without reason",
        b"HTTP/2 404\r\nA: 1\r\n\r\n",
        ("404", {"a": "1"}, "", False),
    ),
    (
        "bare protocol token",
        b"HTTP/1.1\r\nHost: h\r\n\r\nbody",
        ("HTTP/1.1", {"host": "h"}, "body", False),
    ),
    (
        "lowercase http token",
        b"http/1.1 201 Created\r\nA: 1\r\n\r\nb",
        ("201", {"a": "1"}, "b", False),
    ),
    (
        "request line is kept whole",
        b"GET /x HTTP/1.1\r\nHost: h\r\n\r\nbody",
        ("GET /x HTTP/1.1", {"host": "h"}, "body", False),
    ),
    (
        "request line, lowercase",
        b"get /x http/1.1\r\nHost: h\r\n\r\nbody",
        ("get /x http/1.1", {"host": "h"}, "body", False),
    ),
    (
        "unrecognised first line",
        b"Hello there\r\nHost: h\r\n\r\nbody",
        ("", {"host": "h"}, "body", False),
    ),
    ("leading blank line", b"\r\n\r\nbody", ("", {}, "body", False)),
    (
        "only the first blank line splits",
        b"HTTP/1.1 200\r\nA: 1\r\n\r\nbody\n\nmore",
        ("200", {"a": "1"}, "body\n\nmore", False),
    ),
    (
        "headers: names lowered, values stripped, repeats joined, junk skipped",
        b"HTTP/1.1 200\r\nA: 1\r\na: 2\r\nB:\r\nnocolon\r\n  C : x : y \r\n\r\nbody",
        ("200", {"a": "1, 2", "b": "", "c": "x : y"}, "body", False),
    ),
    (
        "invalid utf-8 is replaced",
        b"HTTP/1.1 200 OK\r\nA: \xff\r\n\r\n\xfe",
        ("200", {"a": "�"}, "�", False),
    ),
]


@pytest.mark.parametrize(
    "data,expected", [pytest.param(d, e, id=i) for i, d, e in PARSE_VECTORS]
)
def test_parse_saved_vectors(data, expected):
    assert diff_cmd.parse_saved(data) == expected


def test_parse_saved_truncates_at_two_hundred_thousand_bytes():
    exact = b"x" * 200_000
    assert diff_cmd.parse_saved(exact) == ("", {}, "x" * 200_000, False)
    status, headers, body, truncated = diff_cmd.parse_saved(exact + b"y")
    assert (len(body), truncated) == (200_000, True) and body == "x" * 200_000
    framed = b"HTTP/1.1 200 OK\r\nA: 1\r\n\r\n" + b"x" * 200_000
    status, headers, body, truncated = diff_cmd.parse_saved(framed)
    assert (status, headers, truncated) == ("200", {"a": "1"}, True)
    assert len(body) == 200_000 - len("HTTP/1.1 200 OK\r\nA: 1\r\n\r\n")


def test_render_diff_status_lines():
    def head(left, right):
        return diff_cmd.render_diff(
            diff_cmd.Side("a", left), diff_cmd.Side("b", right)
        ).split("\n")[0]

    assert head("200", "200") == "status: 200"
    assert head("", "") == "status: (none)"
    assert head("200", "404") == "status: 200 -> 404"
    assert head("", "404") == "status: (none) -> 404"
    assert head("GET /x HTTP/1.1", "200") == "status: GET /x HTTP/1.1 -> 200"


def test_render_diff_header_lines_are_sorted_and_skip_date():
    left = diff_cmd.Side(
        "a",
        "200",
        {"b": "1", "date": "monday", "same": "s", "gone": "g", "change": "old"},
        "t",
    )
    right = diff_cmd.Side(
        "b",
        "200",
        {"b": "1", "date": "tuesday", "same": "s", "new": "n", "change": "newer"},
        "t",
    )
    assert diff_cmd.render_diff(left, right) == (
        "status: 200\nheader change: old -> newer\nheader gone: removed g\nheader new: added n\nbody: unchanged\n"
    )


def test_render_diff_date_header_is_ignored_even_when_only_one_side_has_it():
    left = diff_cmd.Side("a", "200", {"date": "x"}, "t")
    right = diff_cmd.Side("b", "200", {}, "t")
    assert diff_cmd.render_diff(left, right) == "status: 200\nbody: unchanged\n"


def test_render_diff_equal_bodies():
    side = diff_cmd.Side("a", "200", {}, "same\n")
    assert (
        diff_cmd.render_diff(side, diff_cmd.Side("b", "200", {}, "same\n"))
        == "status: 200\nbody: unchanged\n"
    )


def test_render_diff_unified_text_diff():
    left = diff_cmd.Side("left.http", "200", {}, "line1\nline2\nline3\n")
    right = diff_cmd.Side("right.http", "200", {}, "line1\nline2 changed\nline3\n")
    assert diff_cmd.render_diff(left, right) == (
        "status: 200\nbody:\n--- left.http\n+++ right.http\n@@ -1,3 +1,3 @@\n line1\n-line2\n+line2 changed\n line3\n"
    )


def test_render_diff_text_without_trailing_newlines():
    left = diff_cmd.Side("a", "200", {}, "one")
    right = diff_cmd.Side("b", "200", {}, "two")
    assert (
        diff_cmd.render_diff(left, right)
        == "status: 200\nbody:\n--- a\n+++ b\n@@ -1 +1 @@\n-one\n+two\n"
    )


def test_render_diff_notes_truncation_between_headers_and_body():
    truncated = diff_cmd.Side("a", "200", {"x": "1"}, "t", True)
    plain = diff_cmd.Side("b", "200", {"x": "2"}, "t", False)
    expected = "status: 200\nheader x: 1 -> 2\nbody compared at the first 200000 bytes\nbody: unchanged\n"
    assert diff_cmd.render_diff(truncated, plain) == expected
    assert diff_cmd.render_diff(plain, truncated) == expected.replace(
        "1 -> 2", "2 -> 1"
    )


def test_render_diff_binary_bodies_are_summarised_by_length():
    left = diff_cmd.Side("a", "200", {}, "ab\x00cd")
    right = diff_cmd.Side("b", "200", {}, "xy")
    assert (
        diff_cmd.render_diff(left, right) == "status: 200\nbody: 5 bytes -> 2 bytes\n"
    )
    assert (
        diff_cmd.render_diff(right, left) == "status: 200\nbody: 2 bytes -> 5 bytes\n"
    )
    assert diff_cmd.render_diff(
        left, diff_cmd.Side("b", "200", {}, "ab\x00cd")
    ).endswith("body: unchanged\n")


def test_defect_the_binary_summary_should_count_bytes():
    left = diff_cmd.Side("a", "200", {}, "hé\x00")
    right = diff_cmd.Side("b", "200", {}, "x")
    assert (
        diff_cmd.render_diff(left, right) == "status: 200\nbody: 4 bytes -> 1 bytes\n"
    )


def test_binary_summary_counts_original_saved_bytes(tmp_path):
    path = tmp_path / "binary.http"
    path.write_bytes(b"HTTP/1.1 200 OK\r\n\r\n\xff\x00\r\n")
    left = diff_cmd.load_side(str(path), None)
    right = diff_cmd.Side("b", "200", {}, "x")
    assert (
        diff_cmd.render_diff(left, right) == "status: 200\nbody: 4 bytes -> 1 bytes\n"
    )


def test_defect_remote_text_should_not_carry_raw_escape_sequences_to_the_terminal():
    left = diff_cmd.Side("a", "200", {}, "t")
    right = diff_cmd.Side("b", "200", {"x-evil": "\x1b[2Jboom"}, "t")
    assert "\x1b" not in diff_cmd.render_diff(left, right)


# --------------------------------------------------------------------------------------------
# diff: resolving the two sides from files
# --------------------------------------------------------------------------------------------

RESP_A = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: x\r\nX-Old: gone\r\nSet-Cookie: a=1\r\n"
    b"Set-Cookie: b=2\r\n\r\nline1\nline2\nline3\n"
)
RESP_B = (
    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nDate: y\r\nX-New: 1\r\nSet-Cookie: a=1\r\n\r\n"
    b"line1\nline2 changed\nline3\n"
)
EXPECTED_AB = (
    "status: 200 -> 404\n"
    "header content-type: text/html -> text/plain\n"
    "header set-cookie: a=1, b=2 -> a=1\n"
    "header x-new: added 1\n"
    "header x-old: removed gone\n"
    "body:\n--- {left}\n+++ {right}\n@@ -1,3 +1,3 @@\n line1\n-line2\n+line2 changed\n line3\n"
)


@pytest.fixture
def saved(ws):
    put(ws / "responses" / "a.http", RESP_A)
    put(ws / "responses" / "b.http", RESP_B)
    return ws / "responses"


def test_load_side_reads_a_bare_name_from_the_responses_directory(saved):
    side = diff_cmd.load_side("a.http", None)
    assert side == diff_cmd.Side(
        "a.http",
        "200",
        {
            "content-type": "text/html",
            "date": "x",
            "x-old": "gone",
            "set-cookie": "a=1, b=2",
        },
        "line1\nline2\nline3\n",
        False,
        body_size=18,
    )


def test_load_side_prefers_a_file_in_the_current_directory_over_responses(
    saved, tmp_path
):
    put(tmp_path / "a.http", b"HTTP/1.1 418 Teapot\r\n\r\ncwd body")
    side = diff_cmd.load_side("a.http", None)
    assert (side.status, side.body) == ("418", "cwd body")
    (tmp_path / "a.http").unlink()
    assert diff_cmd.load_side("a.http", None).status == "200"


def test_load_side_label_is_the_value_as_given(saved, tmp_path):
    put(tmp_path / "sub" / "c.http", b"HTTP/1.1 204\r\n\r\n")
    assert diff_cmd.load_side(str(Path("sub") / "c.http"), None).label == str(
        Path("sub") / "c.http"
    )
    assert diff_cmd.load_side("b.http", None).label == "b.http"


@pytest.mark.parametrize(
    "value", ["nope.http", "sub/a.http", "sub\\a.http", "..", ".", "", "../a.http"]
)
def test_load_side_does_not_search_responses_for_anything_but_a_bare_name(value, saved):
    put(saved / "sub" / "a.http", b"HTTP/1.1 200\r\n\r\nx")
    with pytest.raises(FileNotFoundError) as missing:
        diff_cmd.load_side(value, None)
    assert str(missing.value) == f"No file named {value}."


def test_load_side_refuses_a_directory(saved, tmp_path):
    (saved / "adir").mkdir()
    (tmp_path / "cwd-dir").mkdir()
    for name in ("adir", "cwd-dir"):
        with pytest.raises(FileNotFoundError):
            diff_cmd.load_side(name, None)


def test_load_side_for_a_url_needs_a_client(saved):
    with pytest.raises(FileNotFoundError) as missing:
        diff_cmd.load_side("http://example.test/x", None)
    assert str(missing.value) == "No file named http://example.test/x."


def test_two_saved_responses_are_compared_without_any_network(
    saved, no_network, capsys
):
    code, out, err = call(capsys, diff_cmd, "a.http", "b.http")
    assert (code, err) == (0, "")
    assert out == EXPECTED_AB.format(left="a.http", right="b.http")


def test_a_full_path_works_and_identical_files_report_unchanged(
    saved, no_network, capsys
):
    path_b = str(saved / "b.http")
    code, out, err = call(capsys, diff_cmd, "a.http", path_b)
    assert code == 0 and out == EXPECTED_AB.format(left="a.http", right=path_b)
    assert call(capsys, diff_cmd, "a.http", "a.http") == (
        0,
        "status: 200\nbody: unchanged\n",
        "",
    )


def test_a_missing_file_is_reported_with_exit_two_left_side_first(
    saved, no_network, capsys
):
    assert call(capsys, diff_cmd, "a.http", "nope.http") == (
        2,
        "",
        "No file named nope.http.\n",
    )
    assert call(capsys, diff_cmd, "nope1.http", "nope2.http") == (
        2,
        "",
        "No file named nope1.http.\n",
    )


@pytest.mark.parametrize("timeout", ["0", "-1", "-0.5"])
def test_a_non_positive_timeout_is_refused_before_anything_is_read(
    timeout, ws, no_network, capsys
):
    assert call(capsys, diff_cmd, "--timeout", timeout, "missing-a", "missing-b") == (
        2,
        "",
        "Timeout must be greater than 0.\n",
    )


def test_a_non_http_scheme_is_treated_as_a_file_name(saved, no_network, capsys):
    assert call(capsys, diff_cmd, "ftp://example.test/x", "a.http") == (
        2,
        "",
        "No file named ftp://example.test/x.\n",
    )


@pytest.mark.parametrize(
    "target",
    [
        "http://[bad",
        "http://127.0.0.1:abc/",
        "http://127.0.0.1:99999/",
        "http://127.0.0.1:0/",
        "http://127.0.0.1:/",
        "http://[::1]junk/",
    ],
)
def test_defect_a_malformed_url_should_be_reported_not_raised(
    saved, no_network, capsys, target
):
    code, out, err = call(capsys, diff_cmd, target, "a.http")
    assert code == 2 and not out and "Invalid response URL" in err


@pytest.mark.parametrize(
    "target", ["http://[::1]:1/", "https://127.0.0.1:65535/", "https://[::1]/"]
)
def test_diff_valid_destination_port_controls(target):
    assert diff_cmd._is_http_url(target)


def test_diff_saved_response_escape_sequences_are_neutralized(
    saved, no_network, capsys
):
    put(saved / "esc.http", b"HTTP/1.1 200 OK\r\nX-Evil: \x1b[2Jboom\r\n\r\nt")
    code, out, err = call(capsys, diff_cmd, "a.http", "esc.http")
    assert "\x1b" not in out and "\\x1b[2Jboom" in out


# --------------------------------------------------------------------------------------------
# diff: fetching URL sides (real loopback server behind a verified policy)
# --------------------------------------------------------------------------------------------


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class Lab:
    """A loopback origin that records every request and serves routes; the egress policy permits it."""

    def __init__(self, ws: Path):
        self.ws = ws
        self.seen: list[dict] = []
        self.routes: dict[str, tuple[int, list[tuple[str, str]], bytes]] = {}
        lab = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                lab.seen.append(
                    {
                        "method": "GET",
                        "path": self.path,
                        "headers": {
                            key.lower(): value for key, value in self.headers.items()
                        },
                    }
                )
                status, headers, body = lab.routes.get(
                    self.path, lab.default(self.path)
                )
                time.sleep(lab.delays.get(self.path, 0))
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def date_time_string(self, timestamp=None):
                return f"stamp-for{self.path}"

            def version_string(self):
                return "lab"

            def log_message(self, *args):
                pass

        self.server = _QuietServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.dead = f"http://127.0.0.1:{probe.getsockname()[1]}"
        probe.close()
        self.delays: dict[str, float] = {}
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True
        )
        self.thread.start()
        self.grant()

    @staticmethod
    def default(path):
        return 200, [("Content-Type", "text/plain")], f"body for {path}\n".encode()

    def grant(self):
        document = example_document()
        document.update(
            state="verified", verified_at=datetime.now(timezone.utc).isoformat()
        )
        document["permissions"] = {
            operation: True for operation in document["permissions"]
        }
        document["limits"] = {"requests_per_second": 1000000, "concurrency": 100}
        document["assets"] = [
            {
                "id": f"lab-{index}",
                "origin": origin,
                "paths": ["/"],
                "operations": list(document["permissions"]),
                "methods": ["GET", "HEAD"],
            }
            for index, origin in enumerate((self.base, self.dead))
        ]
        document["exclusions"] = []
        put(self.ws / "policy.json", json.dumps(document))

    def revoke(self):
        (self.ws / "policy.json").unlink()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def lab(ws):
    server = Lab(ws)
    yield server
    server.stop()


def test_url_sides_are_each_fetched_once_with_get_and_diffed(lab, capsys):
    lab.routes["/one"] = (
        200,
        [("Content-Type", "text/plain"), ("X-Path", "/one")],
        b"alpha\nsame\n",
    )
    lab.routes["/two"] = (
        200,
        [("Content-Type", "text/plain"), ("X-Path", "/two")],
        b"beta\nsame\n",
    )
    code, out, err = call(capsys, diff_cmd, f"{lab.base}/one", f"{lab.base}/two")
    assert (code, err) == (0, "")
    assert out == (
        "status: 200\nheader content-length: 11 -> 10\nheader x-path: /one -> /two\n"
        f"body:\n--- {lab.base}/one\n+++ {lab.base}/two\n@@ -1,2 +1,2 @@\n-alpha\n+beta\n same\n"
    )
    assert [(item["method"], item["path"]) for item in lab.seen] == [
        ("GET", "/one"),
        ("GET", "/two"),
    ]


def test_the_date_header_never_shows_up_in_a_diff(lab, capsys):
    code, out, err = call(capsys, diff_cmd, f"{lab.base}/p", f"{lab.base}/q")
    assert "header date" not in out
    assert out.startswith("status: 200\n")


def test_repeated_response_headers_are_joined_with_a_comma(lab, capsys):
    lab.routes["/m1"] = (200, [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")], b"x")
    lab.routes["/m2"] = (200, [("Set-Cookie", "a=1")], b"x")
    code, out, err = call(capsys, diff_cmd, f"{lab.base}/m1", f"{lab.base}/m2")
    assert "header set-cookie: a=1, b=2 -> a=1\n" in out


def test_redirects_are_compared_not_followed(lab, capsys):
    lab.routes["/redir"] = (302, [("Location", "/final")], b"")
    lab.routes["/final"] = (200, [("Content-Type", "text/plain")], b"landed\n")
    code, out, err = call(capsys, diff_cmd, f"{lab.base}/redir", f"{lab.base}/final")
    assert code == 0
    assert (
        out.startswith("status: 302 -> 200\n")
        and "header location: removed /final\n" in out
    )
    assert [item["path"] for item in lab.seen] == ["/redir", "/final"]


def test_url_bodies_are_cut_at_two_hundred_thousand_bytes(lab, capsys):
    header = [("Content-Type", "text/plain")]
    lab.routes["/big-a"] = (200, header, b"z" * 200_000 + b"a")
    lab.routes["/big-b"] = (200, header, b"z" * 200_000 + b"b")
    lab.routes["/edge-a"] = (200, header, b"z" * 200_000)
    lab.routes["/edge-b"] = (200, header, b"z" * 200_000)
    code, out, err = call(capsys, diff_cmd, f"{lab.base}/big-a", f"{lab.base}/big-b")
    assert (
        out == "status: 200\nbody compared at the first 200000 bytes\nbody: unchanged\n"
    )
    code, out, err = call(capsys, diff_cmd, f"{lab.base}/edge-a", f"{lab.base}/edge-b")
    assert out == "status: 200\nbody: unchanged\n"


def test_url_binary_bodies_are_summarised(lab, capsys):
    lab.routes["/bin1"] = (
        200,
        [("Content-Type", "application/octet-stream")],
        b"ab\x00cd",
    )
    lab.routes["/bin2"] = (
        200,
        [("Content-Type", "application/octet-stream")],
        b"xy\x00",
    )
    code, out, err = call(capsys, diff_cmd, f"{lab.base}/bin1", f"{lab.base}/bin2")
    assert (
        out == "status: 200\nheader content-length: 5 -> 3\nbody: 5 bytes -> 3 bytes\n"
    )


def test_file_versus_url_makes_a_single_request(lab, ws, capsys):
    put(
        ws / "responses" / "f.http",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody for /two\n",
    )
    code, out, err = call(capsys, diff_cmd, "f.http", f"{lab.base}/two")
    assert code == 0
    assert [item["path"] for item in lab.seen] == ["/two"]
    assert (
        out
        == "status: 200\nheader content-length: added 14\nheader server: added lab\nbody: unchanged\n"
    )


def test_saved_credentials_are_sent_and_flags_replace_them(lab, ws, capsys):
    session.write_session({"cookie": "sess=SAVED", "authorization": "Bearer SAVEDTOK"})
    diff_cmd.main([f"{lab.base}/s1", f"{lab.base}/s2"])
    assert lab.seen[0]["headers"]["cookie"] == "sess=SAVED"
    assert lab.seen[0]["headers"]["authorization"] == "Bearer SAVEDTOK"
    lab.seen.clear()
    diff_cmd.main(
        [
            "--cookie",
            "x=1",
            "--authorization",
            "Basic abc",
            f"{lab.base}/s1",
            f"{lab.base}/s2",
        ]
    )
    assert lab.seen[0]["headers"]["cookie"] == "x=1"
    assert lab.seen[0]["headers"]["authorization"] == "Basic abc"
    lab.seen.clear()
    diff_cmd.main(["--cookie", "", f"{lab.base}/s1", f"{lab.base}/s2"])
    assert "cookie" not in lab.seen[0]["headers"]
    assert lab.seen[0]["headers"]["authorization"] == "Bearer SAVEDTOK"


@pytest.mark.parametrize(
    "override, expected", [(None, "sess=BASELINE"), ("flag=1", "flag=1"), ("", None)]
)
def test_diff_preserves_baseline_credentials_without_response_cookies(
    lab, capsys, override, expected
):
    session.write_session(
        {"cookie": "sess=BASELINE", "authorization": "Bearer BASELINE"}
    )
    lab.routes["/jar1"] = (200, [("Set-Cookie", "response=poison; Path=/")], b"x")
    arguments = [] if override is None else ["--cookie", override]
    assert diff_cmd.main([*arguments, f"{lab.base}/jar1", f"{lab.base}/jar2"]) == 0
    assert len(lab.seen) == 2
    for request in lab.seen:
        assert request["headers"].get("cookie") == expected
        assert request["headers"]["authorization"] == "Bearer BASELINE"


@pytest.mark.parametrize("status", [200, 302])
def test_right_request_does_not_carry_cookies_set_by_the_left_response(
    lab, capsys, status
):
    lab.routes["/jar1"] = (status, [("Set-Cookie", "jar=1")], b"x")
    diff_cmd.main([f"{lab.base}/jar1", f"{lab.base}/jar2"])
    assert "cookie" not in lab.seen[1]["headers"]


def test_an_out_of_scope_url_is_refused_before_any_request(lab, ws, capsys):
    put(ws / "scope.txt", "other.test\n")
    code, out, err = call(capsys, diff_cmd, "http://evil.test/x", f"{lab.base}/ok")
    assert (code, out) == (2, "")
    assert err == workspace.explain_block("evil.test") + "\n"
    assert "bughunt scope add evil.test" in err
    code, out, err = call(capsys, diff_cmd, f"{lab.base}/ok", "http://evil.test/x")
    assert (code, out) == (2, "") and "evil.test" in err
    assert lab.seen == []


def test_the_scope_check_runs_before_a_missing_file_is_noticed(ws, no_network, capsys):
    code, out, err = call(capsys, diff_cmd, "http://evil.test/x", "no-such-file")
    assert (code, out) == (2, "")
    assert err == workspace.explain_block("evil.test") + "\n"
    assert "no scope file" in err


def test_a_url_without_a_policy_is_blocked_and_reported_as_a_fetch_failure(lab, capsys):
    lab.revoke()
    code, out, err = call(capsys, diff_cmd, f"{lab.base}/a", f"{lab.base}/b")
    assert (code, out, err) == (1, "", "Could not fetch: PolicyBlocked\n")
    assert lab.seen == []


def test_the_timeout_flag_bounds_each_fetch(lab, capsys):
    lab.delays["/slow"] = 1.5
    code, out, err = call(
        capsys, diff_cmd, "--timeout", "0.3", f"{lab.base}/fast", f"{lab.base}/slow"
    )
    assert (code, out, err) == (1, "", "Could not fetch: ReadTimeout\n")


def test_timeout_and_insecure_reach_the_http_client_and_one_client_serves_both_sides(
    lab, monkeypatch, capsys
):
    built = []
    real_client = egress.client

    def spy(**kwargs):
        built.append(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(egress, "client", spy)
    assert (
        diff_cmd.main(
            ["--insecure", "--timeout", "7", f"{lab.base}/a", f"{lab.base}/b"]
        )
        == 0
    )
    assert len(built) == 1
    assert (built[0]["verify"], built[0]["timeout"], built[0]["follow_redirects"]) == (
        False,
        7.0,
        False,
    )
    built.clear()
    assert diff_cmd.main([f"{lab.base}/a", f"{lab.base}/b"]) == 0
    assert (built[0]["verify"], built[0]["timeout"]) == (True, 10.0)


def test_no_client_is_built_when_both_sides_are_files(saved, monkeypatch, capsys):
    built = []
    monkeypatch.setattr(egress, "client", lambda **kwargs: built.append(kwargs))
    assert diff_cmd.main(["a.http", "b.http"]) == 0
    assert built == []


def test_a_refused_connection_is_reported_with_the_error_class(lab, capsys):
    code, out, err = call(
        capsys, diff_cmd, "--timeout", "3", f"{lab.dead}/x", f"{lab.base}/b"
    )
    assert (code, out, err) == (1, "", "Could not fetch: ConnectError\n")
    assert lab.seen == []


# --------------------------------------------------------------------------------------------
# clutch
# --------------------------------------------------------------------------------------------

REQ_IN = (
    b"GET /a?x=1 HTTP/1.1\r\nHost: Example.COM.\r\nCookie: secret=1\r\nAuthorization: Bearer zzz\r\n"
    b"Proxy-Authorization: Basic q\r\nX-Other: ok\r\n\r\nbody-bytes"
)
REQ_OUT = b"POST /login HTTP/1.1\r\nHost: evil.test:8443\r\n\r\n"
REQ_NOHOST = b"GET /x HTTP/1.1\r\n\r\n"
REQ_ABSOLUTE = b"GET http://example.com/p?q=2 HTTP/1.1\r\n\r\n"
REQ_LOOPBACK = b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n"
REQ_LOOSE = b"get noslash HTTP/1.1\r\nHost: example.com\r\n\r\n"


@pytest.fixture
def held(ws):
    put(ws / "scope.txt", "example.com\n")
    return ws / "requests"


def test_held_is_a_frozen_dataclass_with_this_field_order():
    assert [field.name for field in dataclasses.fields(clutch.Held)] == [
        "name",
        "method",
        "host",
        "path",
        "scope",
    ]
    assert clutch.Held.__dataclass_params__.frozen is True
    row = clutch.Held("n", "GET", "h", "/", "in scope")
    with pytest.raises(dataclasses.FrozenInstanceError):
        row.name = "x"
    assert row == clutch.Held("n", "GET", "h", "/", "in scope")


def test_list_requests_without_the_directory_is_empty(ws):
    assert clutch.list_requests() == []


def test_list_requests_rows(held):
    put(held / "in.http", REQ_IN)
    put(held / "out.http", REQ_OUT)
    put(held / "nohost.http", REQ_NOHOST)
    put(held / "abs.http", REQ_ABSOLUTE)
    put(held / "loop.http", REQ_LOOPBACK)
    put(held / "loose.http", REQ_LOOSE)
    assert clutch.list_requests() == [
        clutch.Held("abs.http", "GET", "example.com", "/p?q=2", "in scope"),
        clutch.Held("in.http", "GET", "example.com", "/a?x=1", "in scope"),
        clutch.Held("loop.http", "GET", "::1", "/", "in scope"),
        clutch.Held("loose.http", "GET", "example.com", "/noslash", "in scope"),
        clutch.Held("nohost.http", "GET", "-", "/x", "no host"),
        clutch.Held("out.http", "POST", "evil.test", "/login", "outside"),
    ]


def test_list_requests_sorts_by_name_ignoring_case_and_skips_directories(held):
    for name in ("b.http", "A.http", "c.http", "D.http"):
        put(held / name, REQ_IN)
    (held / "subdir").mkdir()
    put(held / "subdir" / "inner.http", REQ_IN)
    assert [row.name for row in clutch.list_requests()] == [
        "A.http",
        "b.http",
        "c.http",
        "D.http",
    ]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\n\n",
        b"GET\r\nHost: x\r\n\r\n",
        b"GET / HTTP/1.1\r\nnocolon\r\n\r\n",
        b"GET / HTTP/1.1\r\n: nameless\r\n\r\n",
    ],
)
def test_unparsable_files_are_listed_as_unreadable(raw, held):
    put(held / "bad.http", raw)
    assert clutch.list_requests() == [
        clutch.Held("bad.http", "?", "?", "?", "unreadable")
    ]


def test_the_size_cap_is_one_million_bytes_inclusive(held):
    head = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    put(held / "exact.http", head + b"A" * (1_000_000 - len(head)))
    put(held / "over.http", head + b"A" * (1_000_001 - len(head)))
    assert (held / "exact.http").stat().st_size == 1_000_000
    rows = {row.name: row for row in clutch.list_requests()}
    assert rows["exact.http"] == clutch.Held(
        "exact.http", "GET", "example.com", "/", "in scope"
    )
    assert rows["over.http"] == clutch.Held("over.http", "?", "?", "?", "too large")


def test_without_a_scope_file_only_loopback_hosts_are_in_scope(ws):
    put(ws / "requests" / "a.http", REQ_IN)
    put(ws / "requests" / "b.http", REQ_LOOPBACK)
    assert [row.scope for row in clutch.list_requests()] == ["outside", "in scope"]


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\nHost: example.com:abc\r\n\r\n",
        b"GET http://example.com:99999/ HTTP/1.1\r\n\r\n",
    ],
)
def test_defect_a_bad_port_should_only_mark_its_own_row(held, capsys, raw):
    put(held / "ok.http", REQ_IN)
    put(held / "badport.http", raw)
    rows = {row.name: row for row in clutch.list_requests()}
    assert (
        rows["badport.http"].scope == "unreadable"
        and rows["ok.http"].scope == "in scope"
    )
    code, output, _error = call(capsys, clutch, "--plain")
    assert code == 0
    assert "badport.http" in output and "unreadable" in output and "ok.http" in output


def test_format_row_plain_and_colour():
    row = clutch.Held("n.http", "GET", "example.com", "/a", "in scope")
    assert clutch.format_row(row, False) == "n.http\tGET\texample.com\t/a\tin scope"
    assert clutch.format_row(row, True) == (
        f"  {CYAN}GET   {RESET} {WHITE}example.com /a{RESET}  {WHITE}in scope{RESET}  {DIM}n.http{RESET}"
    )
    outside = clutch.Held("n.http", "DELETE", "evil.test", "/x", "outside")
    assert clutch.format_row(outside, True) == (
        f"  {CYAN}DELETE{RESET} {WHITE}evil.test /x{RESET}  {YELLOW}outside{RESET}  {DIM}n.http{RESET}"
    )
    assert (
        clutch.format_row(clutch.Held("n", "?", "?", "?", "unreadable"), True).count(
            YELLOW
        )
        == 1
    )


def test_main_lists_rows_on_stdout_and_a_summary_on_stderr(held, capsys):
    put(held / "in.http", REQ_IN)
    put(held / "out.http", REQ_OUT)
    for argv in (["--plain"], ["--plain", "list"]):
        code, out, err = call(capsys, clutch, *argv)
        assert code == 0
        assert out == (
            "in.http\tGET\texample.com\t/a?x=1\tin scope\n"
            "out.http\tPOST\tevil.test\t/login\toutside\n"
        )
        assert err == "2 saved request(s)\nclutch show <name> prints one.\n"


def test_main_with_nothing_saved_explains_how_requests_get_there(ws, capsys):
    expected = (
        "no saved requests\nsnare writes requests/example.com-snare-0001.http while it listens.\n"
        "clutch show <name> prints one.\n"
    )
    assert call(capsys, clutch, "--plain") == (0, "", expected)
    (ws / "requests").mkdir(parents=True)
    assert call(capsys, clutch, "--plain") == (0, "", expected)


def test_main_colours_rows_on_a_terminal(held, tty):
    out, err = tty()
    put(held / "in.http", REQ_IN)
    clutch.main([])
    assert (
        out.getvalue()
        == clutch.format_row(
            clutch.Held("in.http", "GET", "example.com", "/a?x=1", "in scope"), True
        )
        + "\n"
    )


def test_redact_blanks_cookie_authorization_and_proxy_authorization():
    text = clutch.redact(
        b"GET / HTTP/1.1\r\nCookie: a\r\ncOOkie: b\r\nAUTHORIZATION: c\r\n"
        b"Proxy-Authorization: d\r\nHost: h\r\nX-Api-Key: kept\r\n\r\nbody"
    )
    assert text == (
        "GET / HTTP/1.1\r\nCookie: [blank]\r\ncOOkie: [blank]\r\nAUTHORIZATION: [blank]\r\n"
        "Proxy-Authorization: [blank]\r\nHost: h\r\nX-Api-Key: kept\r\n\r\nbody"
    )


def test_redact_rebuilds_the_message_with_crlf_and_decodes_the_body_as_latin1():
    assert (
        clutch.redact(b"GET /\nHost: h\n\nbody")
        == "GET / HTTP/1.1\r\nHost: h\r\n\r\nbody"
    )
    assert clutch.redact(b"post / http/1.0\nX: 1") == "POST / http/1.0\r\nX: 1\r\n\r\n"
    assert (
        clutch.redact(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n\xff\xfe")
        == "GET / HTTP/1.1\r\nHost: h\r\n\r\nÿþ"
    )


def test_redact_unfolds_continuation_lines_and_blanks_a_folded_secret_completely():
    assert clutch.redact(b"GET / HTTP/1.1\r\nX: a\r\n b\r\nHost: h\r\n\r\n") == (
        "GET / HTTP/1.1\r\nX: a b\r\nHost: h\r\n\r\n"
    )
    assert clutch.redact(
        b"GET / HTTP/1.1\r\nCookie: a\r\n  b=2\r\nHost: h\r\n\r\n"
    ) == ("GET / HTTP/1.1\r\nCookie: [blank]\r\nHost: h\r\n\r\n")


@pytest.mark.parametrize(
    "raw", [b"", b"GET\r\n\r\n", b"GET / HTTP/1.1\r\nnocolon\r\n\r\n"]
)
def test_redact_raises_value_error_for_unparsable_input(raw):
    with pytest.raises(ValueError):
        clutch.redact(raw)


def test_show_prints_the_request_with_secrets_blanked(held, capsys):
    put(held / "in.http", REQ_IN)
    code, out, err = call(capsys, clutch, "--plain", "show", "in.http")
    assert code == 0
    assert out == (
        "GET /a?x=1 HTTP/1.1\r\nHost: Example.COM.\r\nCookie: [blank]\r\nAuthorization: [blank]\r\n"
        "Proxy-Authorization: [blank]\r\nX-Other: ok\r\n\r\nbody-bytes\n"
    )
    assert err == "Saved request in.http. repeater can send that file again.\n"
    assert "secret=1" not in out and "zzz" not in out
    assert (held / "in.http").read_bytes() == REQ_IN


def test_show_adds_a_newline_only_when_the_text_does_not_end_with_one(held, capsys):
    put(held / "out.http", REQ_OUT)
    assert (
        call(capsys, clutch, "--plain", "show", "out.http")[1]
        == "POST /login HTTP/1.1\r\nHost: evil.test:8443\r\n\r\n"
    )
    put(held / "body.http", b"POST / HTTP/1.1\r\nHost: h\r\n\r\npayload\n")
    assert (
        call(capsys, clutch, "--plain", "show", "body.http")[1]
        == "POST / HTTP/1.1\r\nHost: h\r\n\r\npayload\n"
    )


@pytest.mark.parametrize(
    "name", ["", ".", "..", "../x", "sub/../in.http", "in.http/", "a/b", "/abs"]
)
def test_show_rejects_anything_but_a_bare_file_name(name, held, capsys):
    put(held / "in.http", REQ_IN)
    assert call(capsys, clutch, "--plain", "show", name) == (
        2,
        "",
        "Give the file name inside the requests directory.\n",
    )


def test_show_reports_a_missing_file_or_a_directory(held, ws, capsys):
    assert call(capsys, clutch, "--plain", "show", "nope.http") == (
        2,
        "",
        "No saved request named nope.http.\n",
    )
    (held).mkdir(parents=True, exist_ok=True)
    (held / "adir").mkdir()
    assert call(capsys, clutch, "--plain", "show", "adir") == (
        2,
        "",
        "No saved request named adir.\n",
    )


def test_show_refuses_files_over_one_million_bytes(held, capsys):
    head = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    put(held / "over.http", head + b"A" * (1_000_001 - len(head)))
    assert call(capsys, clutch, "--plain", "show", "over.http") == (
        2,
        "",
        "over.http is larger than 1000000 bytes.\n",
    )
    put(held / "exact.http", head + b"A" * (1_000_000 - len(head)))
    assert call(capsys, clutch, "--plain", "show", "exact.http")[0] == 0


@pytest.mark.parametrize(
    "raw", [b"", b"GET\r\nHost: x\r\n\r\n", b"GET / HTTP/1.1\r\nnocolon\r\n\r\n"]
)
def test_show_reports_a_parse_failure_with_the_parser_message_and_exit_one(
    raw, held, capsys
):
    put(held / "bad.http", raw)
    with pytest.raises(ValueError) as parsed:
        repeater.parse_raw(raw)
    assert call(capsys, clutch, "--plain", "show", "bad.http") == (
        1,
        "",
        f"{parsed.value}\n",
    )


def test_show_does_not_need_a_scope_file(ws, capsys):
    put(ws / "requests" / "in.http", REQ_IN)
    assert call(capsys, clutch, "--plain", "show", "in.http")[0] == 0


def test_show_should_not_echo_credentials_embedded_in_the_target(held, capsys):
    put(
        held / "userinfo.http",
        b"GET http://user:hunter2@example.com/p HTTP/1.1\r\n\r\n",
    )
    code, out, err = call(capsys, clutch, "--plain", "show", "userinfo.http")
    assert "hunter2" not in out and "user:" not in out
    assert "http://[blank]@example.com/p" in out


def test_defect_captured_text_should_not_carry_raw_escape_sequences_to_the_terminal(
    held, capsys
):
    put(held / "esc.http", b"GET /\x1b[31mred HTTP/1.1\r\nHost: example.com\r\n\r\n")
    code, out, err = call(capsys, clutch, "--plain")
    assert "\x1b" not in out
