"""Characterization oracle for `bughunt.console.options` (M2 clean-room rebuild, spec section 3).

The argparse->form mapping is exercised through the public `load_spec` (the `scan` branch takes a
parser factory, so any hand-built parser can be mapped). `render_argv`, `set_option`,
`unset_option`, `print_settings`, `show_options` and `prepare_argv` are pinned with the spec's
verified vectors (12.2) plus hand-built specs for the corners nothing else reaches.
"""

from __future__ import annotations

import argparse
import shlex
import types

import pytest

from bughunt.console import options
from bughunt.console.options import Option, Spec, SpecError, load_spec, render_argv

from console_support import (  # noqa: F401  (env is a pytest fixture)
    BUILD_PARSER,
    SCANNER_FILE,
    env,
    make_project,
)


def spec_of(parser: argparse.ArgumentParser) -> Spec:
    return load_spec("scan", tool_file=SCANNER_FILE, build_parser=lambda prog: parser)


def scan_spec() -> Spec:
    return load_spec("scan", tool_file=SCANNER_FILE, build_parser=BUILD_PARSER)


def policy_spec() -> Spec:
    return load_spec("policy", tool_file=SCANNER_FILE, build_parser=None)


def by_name(spec: Spec) -> dict[str, Option]:
    return {opt.name: opt for opt in spec.options}


def option(
    name,
    kind="value",
    flags=(),
    *,
    subcommand="",
    repeatable=False,
    choices=(),
    store_false=False,
    required=False,
    default="",
):
    return Option(
        name=name,
        dest=name.lower(),
        flags=tuple(flags),
        kind=kind,
        required=required,
        help="",
        choices=tuple(choices),
        subcommand=subcommand,
        repeatable=repeatable,
        store_false=store_false,
        default=default,
    )


@pytest.mark.parametrize("platform", ["win32", "linux", "darwin"])
@pytest.mark.parametrize(
    "raw",
    [
        "'a b' \"c d\" e\\ f ''",
        "'" + r'{"name":"a b","path":"C:\\Temp\\input.txt"}' + "'",
        r"value\=other escaped\'quote empty=\"\"",
        r"'C:\Temp\paths.txt' '/tmp/a b'",
    ],
)
def test_split_words_keeps_shell_quoting_and_payloads(monkeypatch, platform, raw):
    monkeypatch.setattr(
        options, "sys", types.SimpleNamespace(platform=platform), raising=False
    )
    assert options.split_words(raw) == shlex.split(raw)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_split_words_keeps_posix_backslash_rules(monkeypatch, platform):
    monkeypatch.setattr(
        options, "sys", types.SimpleNamespace(platform=platform), raising=False
    )
    raw = r"scan --paths-file C:\Temp\paths.txt"
    assert options.split_words(raw) == shlex.split(raw)


@pytest.mark.parametrize(
    "path", [r"C:\Temp\a=b\paths.txt", r"\\server\share\a=b\paths.txt"]
)
@pytest.mark.parametrize("separator", [" ", "="])
def test_split_words_preserves_equals_inside_windows_paths(
    monkeypatch, path, separator
):
    monkeypatch.setattr(
        options, "sys", types.SimpleNamespace(platform="win32"), raising=False
    )
    raw = "scan --wordlist" + separator + path
    expected = (
        ["scan", "--wordlist", path]
        if separator == " "
        else ["scan", "--wordlist=" + path]
    )
    assert options.split_words(raw) == expected


def test_raw_repeatable_windows_paths_roundtrip_saved_settings(env, monkeypatch):
    monkeypatch.setattr(
        options, "sys", types.SimpleNamespace(platform="win32"), raising=False
    )
    spec = Spec(
        options=(option("FILE", flags=("--file",), repeatable=True),),
        subcommands=(),
        command_name="",
    )
    monkeypatch.setattr(options, "load_spec", lambda *args, **kwargs: spec)
    saved = {}
    raw = r'C:\Temp\paths.txt "C:\Temp Folder\more.txt"'
    assert options.set_option(
        "x", saved, "FILE", raw, tool_file=SCANNER_FILE, build_parser=None
    )
    assert render_argv(spec, saved, []) == [
        "--file",
        r"C:\Temp\paths.txt",
        "--file",
        r"C:\Temp Folder\more.txt",
    ]


# --------------------------------------------------------------------------------------
# 3.2 argparse -> Spec mapping
# --------------------------------------------------------------------------------------


def test_option_fields_and_name_is_the_upper_cased_dest():
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--port-range", "-r", help="a range")
    opt = by_name(spec_of(parser))["PORT_RANGE"]
    assert (opt.name, opt.dest, opt.flags, opt.kind, opt.required, opt.help) == (
        "PORT_RANGE",
        "port_range",
        ("--port-range", "-r"),
        "value",
        False,
        "a range",
    )
    assert (
        opt.choices == ()
        and opt.subcommand == ""
        and opt.repeatable is False
        and opt.store_false is False
    )
    assert opt.default == ""


def test_option_records_are_immutable():
    opt = by_name(scan_spec())["PORTS"]
    with pytest.raises(Exception):
        opt.name = "OTHER"


def test_help_actions_are_skipped_and_suppressed_help_is_hidden():
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--shown")
    parser.add_argument("--hidden", help=argparse.SUPPRESS)
    spec = spec_of(parser)
    assert [opt.name for opt in spec.options] == ["SHOWN"]


def test_kind_bool_value_and_positional_omit_the_version_action():
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("target", nargs="?")
    parser.add_argument("--flag", action="store_true")
    parser.add_argument("--no-flag", dest="flag2", action="store_false")
    parser.add_argument("--const-flag", action="store_const", const=True)
    parser.add_argument("--const-five", action="store_const", const=5)
    parser.add_argument("--val")
    parser.add_argument("--version", action="version", version="9")
    kinds = {opt.name: opt.kind for opt in spec_of(parser).options}
    assert kinds == {
        "TARGET": "positional",
        "FLAG": "bool",
        "FLAG2": "bool",
        "CONST_FLAG": "bool",
        "CONST_FIVE": "value",
        "VAL": "value",
    }


def test_store_false_is_recorded_only_for_store_false_actions():
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--on", action="store_true")
    parser.add_argument("--off", action="store_false")
    flags = {opt.name: opt.store_false for opt in spec_of(parser).options}
    assert flags == {"ON": False, "OFF": True}


@pytest.mark.parametrize(
    "kwargs,repeatable",
    [
        ({"action": "append"}, True),
        ({"nargs": "+"}, True),
        ({"nargs": "*"}, True),
        ({"nargs": 2}, False),
        ({"nargs": "?"}, False),
        ({}, False),
    ],
)
def test_repeatable_means_append_or_plus_or_star(kwargs, repeatable):
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--opt", **kwargs)
    assert by_name(spec_of(parser))["OPT"].repeatable is repeatable


@pytest.mark.parametrize(
    "kwargs,required",
    [
        ({}, True),
        ({"nargs": "?"}, False),
        ({"nargs": "*"}, False),
        ({"nargs": "+"}, True),
        ({"nargs": 2}, True),
    ],
)
def test_positional_required_unless_nargs_question_or_star(kwargs, required):
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("item", **kwargs)
    assert by_name(spec_of(parser))["ITEM"].required is required


def test_optional_required_follows_the_action():
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--must", required=True)
    parser.add_argument("--may")
    flags = {opt.name: opt.required for opt in spec_of(parser).options}
    assert flags == {"MUST": True, "MAY": False}


def test_choices_are_stringified():
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--level", type=int, choices=[1, 2, 3])
    parser.add_argument("--mode", choices=["a", "b"])
    spec = by_name(spec_of(parser))
    assert spec["LEVEL"].choices == ("1", "2", "3")
    assert spec["MODE"].choices == ("a", "b")


def test_flags_keep_declaration_order_and_both_spellings():
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("-H", "--header", action="append")
    parser.add_argument("--authorized", "--i-own-this", action="store_true")
    spec = by_name(spec_of(parser))
    assert spec["HEADER"].flags == ("-H", "--header")
    assert spec["AUTHORIZED"].flags == ("--authorized", "--i-own-this")


def test_declaration_order_is_preserved():
    parser = argparse.ArgumentParser(prog="t")
    for name in ("--zeta", "--alpha", "--mid"):
        parser.add_argument(name)
    assert [opt.name for opt in spec_of(parser).options] == ["ZETA", "ALPHA", "MID"]


def test_no_subparsers_means_empty_command_name_and_no_subcommands():
    spec = spec_of(argparse.ArgumentParser(prog="t"))
    assert spec.command_name == "" and spec.subcommands == () and spec.options == ()


def _subcommand_parser(dest="command"):
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--global-opt")
    sub = parser.add_subparsers(dest=dest, required=True)
    first = sub.add_parser("first", help="the first one")
    first.add_argument("--only-first")
    first.add_argument("file")
    second = sub.add_parser("second")
    second.add_argument("file")
    second.add_argument("--only-second", action="store_true")
    return parser


def test_subparsers_are_flattened_with_the_command_positional_last():
    spec = spec_of(_subcommand_parser())
    assert [(o.name, o.subcommand) for o in spec.options] == [
        ("GLOBAL_OPT", ""),
        ("ONLY_FIRST", "first"),
        ("FILE", "first"),
        ("FILE", "second"),
        ("ONLY_SECOND", "second"),
        ("COMMAND", ""),
    ]
    assert spec.subcommands == (("first", "the first one"), ("second", ""))
    assert spec.command_name == "COMMAND"


def test_command_positional_record():
    command = by_name(spec_of(_subcommand_parser()))["COMMAND"]
    assert (command.kind, command.flags, command.dest) == ("positional", (), "command")
    assert command.required is True
    assert command.help == "Subcommand."
    assert command.choices == ("first", "second")
    assert command.subcommand == "" and command.repeatable is False


@pytest.mark.parametrize(
    "dest,expected", [("command", "COMMAND"), ("cmd", "COMMAND"), ("action", "ACTION")]
)
def test_command_name_comes_from_the_subparsers_dest(dest, expected):
    assert spec_of(_subcommand_parser(dest)).command_name == expected


def test_subparsers_without_required_make_the_command_optional():
    parser = argparse.ArgumentParser(prog="t")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("go")
    assert by_name(spec_of(parser))["COMMAND"].required is False


def test_equivalent_inherited_global_options_have_one_canonical_form_field():
    parser = argparse.ArgumentParser(prog="t")
    commands = parser.add_subparsers(dest="command")
    parser.add_argument("--quiet", action="store_true")
    for name in ("first", "second"):
        child = commands.add_parser(name)
        child.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS)
        child.add_argument("--target")
    spec = spec_of(parser)
    assert [option.subcommand for option in spec.options if option.dest == "quiet"] == [
        ""
    ]
    assert [
        option.subcommand for option in spec.options if option.dest == "target"
    ] == ["first", "second"]


@pytest.mark.parametrize(
    "parent_options,child_options",
    [
        ({"type": int}, {"type": str}),
        ({"action": "store_true"}, {"action": "store_false"}),
        ({"dest": "parent"}, {"dest": "child"}),
        ({"choices": ["a"]}, {"choices": ["b"]}),
        ({}, {"required": True}),
    ],
)
def test_distinct_subcommand_option_semantics_keep_their_own_fields(
    parent_options, child_options
):
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--setting", **parent_options)
    child = parser.add_subparsers(dest="command").add_parser("go")
    child.add_argument("--setting", default=argparse.SUPPRESS, **child_options)
    assert [
        option.subcommand
        for option in spec_of(parser).options
        if option.flags == ("--setting",)
    ] == ["", "go"]


def test_scan_parser_maps_to_sixty_options():
    spec = scan_spec()
    kinds = [opt.kind for opt in spec.options]
    assert len(spec.options) == 60
    assert (kinds.count("positional"), kinds.count("bool"), kinds.count("value")) == (
        1,
        26,
        33,
    )
    assert spec.command_name == "" and spec.subcommands == ()
    assert [o.name for o in spec.options][:10] == [
        "TARGETS",
        "DRY_RUN",
        "TARGETS_FILE",
        "COMMON",
        "PORTS",
        "PORT_RANGE",
        "ALL",
        "PORTS_FILE",
        "EXCLUDE_PORTS",
        "AUTHORIZED",
    ]
    assert spec.options[0].name == "TARGETS" and spec.options[0].kind == "positional"
    assert [o.name for o in spec.options if o.repeatable] == ["TARGETS", "HEADER"]
    assert [(o.name, o.choices) for o in spec.options if o.choices] == [
        ("METHOD", ("GET", "HEAD", "OPTIONS", "POST"))
    ]
    assert not any(o.required or o.store_false for o in spec.options)


def test_builtin_policy_form_has_the_check_subcommand():
    spec = policy_spec()
    assert ("check", "") in spec.subcommands
    assert spec.command_name == "COMMAND"


# --------------------------------------------------------------------------------------
# 3.3 default notes
# --------------------------------------------------------------------------------------


def _default(**kwargs) -> str:
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--opt", **kwargs)
    return by_name(spec_of(parser))["OPT"].default


@pytest.mark.parametrize(
    "default,expected",
    [
        (None, ""),
        (argparse.SUPPRESS, ""),
        (True, ""),
        (False, ""),
        (0, "0"),
        (256, "256"),
        (1.2, "1.2"),
        ("GET", "GET"),
        ("", ""),
        ("a   b\t\nc", "a b c"),
        ("x" * 36, "x" * 36),
        ("x" * 37, "x" * 33 + "..."),
        ("x" * 80, "x" * 33 + "..."),
        # a space at index 15 is too early to cut on; index 16 is the first that cuts
        ("a" * 15 + " " + "b" * 40, "a" * 15 + " " + "b" * 17 + "..."),
        ("a" * 16 + " " + "b" * 40, "a" * 16 + "..."),
        (
            "Bughunt/2.3 (+authorized surface mapping)",
            "Bughunt/2.3 (+authorized surface...",
        ),
        (
            "alpha beta gamma delta epsilon zeta eta theta",
            "alpha beta gamma delta epsilon...",
        ),
    ],
)
def test_default_note_rules(default, expected):
    assert _default(default=default) == expected


@pytest.mark.parametrize(
    "kwargs",
    [
        {"action": "store_true", "default": "ignored"},
        {"action": "store_false", "default": "ignored"},
        {"action": "append", "default": ["x"]},
        {"action": "count", "default": 3},
    ],
    ids=["store_true", "store_false", "append", "count"],
)
def test_default_note_is_empty_for_switch_append_and_count_actions(kwargs):
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--opt", **kwargs)
    assert by_name(spec_of(parser))["OPT"].default == ""


# --------------------------------------------------------------------------------------
# 3.4 load_spec resolution order
# --------------------------------------------------------------------------------------


def test_scan_without_a_parser_factory_raises_spec_error():
    with pytest.raises(SpecError) as raised:
        load_spec("scan", tool_file=SCANNER_FILE, build_parser=None)
    assert raised.value.message.strip()
    assert str(raised.value)


def test_scan_spec_is_built_from_the_scan_prog_name():
    seen = []

    def factory(prog):
        seen.append(prog)
        return BUILD_PARSER(prog)

    load_spec("scan", tool_file=SCANNER_FILE, build_parser=factory)
    assert seen == ["bughunt scan"]


@pytest.mark.parametrize("name", ["tcurl"])
def test_disabled_references_raise_before_any_lookup(monkeypatch, name):
    def boom(*args, **kwargs):
        raise AssertionError("locate_script must not run for a disabled tool")

    monkeypatch.setattr(options, "locate_script", boom)
    monkeypatch.setattr(options, "DISABLED_REFERENCES", frozenset({name}))
    with pytest.raises(SpecError, match="disabled") as raised:
        load_spec(name, tool_file=SCANNER_FILE, build_parser=None)
    assert name in raised.value.message


def test_unknown_module_raises():
    with pytest.raises(SpecError) as raised:
        load_spec("nope", tool_file=SCANNER_FILE, build_parser=None)
    assert "nope" in raised.value.message


def test_builtin_module_form_is_read_from_its_parser():
    spec = load_spec("redirect", tool_file=SCANNER_FILE, build_parser=None)
    assert "COOKIE" in by_name(spec)


def test_builtin_load_failure_becomes_spec_error(monkeypatch):
    import bughunt.modules as modules

    def broken(name):
        raise ImportError("kaput")

    monkeypatch.setattr(modules, "load_builtin", broken)
    with pytest.raises(SpecError) as raised:
        load_spec("dns", tool_file=SCANNER_FILE, build_parser=None)
    assert "dns" in raised.value.message and "kaput" in raised.value.message


def _patched_builtin(monkeypatch, module):
    import bughunt.modules as modules

    monkeypatch.setattr(modules, "load_builtin", lambda name: module)


def test_builtin_without_a_parser_factory_raises(monkeypatch):
    import types

    _patched_builtin(monkeypatch, types.ModuleType("empty"))
    with pytest.raises(SpecError) as raised:
        load_spec("dns", tool_file=SCANNER_FILE, build_parser=None)
    assert raised.value.message.strip()


def test_parser_factory_is_tried_as_build_parser_then_create_parser(monkeypatch):
    import types

    module = types.ModuleType("m")
    module.build_parser = "not callable"
    module.create_parser = lambda: _subcommand_parser()
    _patched_builtin(monkeypatch, module)
    assert (
        load_spec("dns", tool_file=SCANNER_FILE, build_parser=None).command_name
        == "COMMAND"
    )


def test_parser_factory_is_retried_with_the_program_name_on_type_error(monkeypatch):
    import types

    seen = []

    def needs_prog(prog):
        seen.append(prog)
        return argparse.ArgumentParser(prog=prog)

    module = types.ModuleType("m")
    module.build_parser = needs_prog
    _patched_builtin(monkeypatch, module)
    load_spec("dns", tool_file=SCANNER_FILE, build_parser=None)
    assert seen == ["bughunt"]


def test_parser_factory_returning_a_non_parser_is_skipped(monkeypatch):
    import types

    module = types.ModuleType("m")
    module.build_parser = lambda: object()
    module.create_parser = lambda: argparse.ArgumentParser(prog="t")
    _patched_builtin(monkeypatch, module)
    assert load_spec("dns", tool_file=SCANNER_FILE, build_parser=None).options == ()


def test_reference_script_missing_from_disk_raises(env):
    tool_file = make_project(env.root)
    with pytest.raises(SpecError) as raised:
        load_spec("pulse", tool_file=tool_file, build_parser=None)
    assert raised.value.message.strip()


def test_reference_alias_resolves_to_its_command(env):
    tool_file = make_project(
        env.root,
        {
            "ct": "import argparse\ndef build_parser():\n    p = argparse.ArgumentParser()\n    p.add_argument('--x')\n    return p\n"
        },
    )
    assert "X" in by_name(
        load_spec("crt-scout", tool_file=tool_file, build_parser=None)
    )


def test_reference_script_that_needs_a_missing_package_is_reported(env):
    tool_file = make_project(
        env.root, {"pulse": "import definitely_not_installed_pkg_xyz\n"}
    )
    with pytest.raises(SpecError) as raised:
        load_spec("pulse", tool_file=tool_file, build_parser=None)
    assert "definitely_not_installed_pkg_xyz" in raised.value.message


def test_reference_script_that_fails_to_import_is_reported(env):
    tool_file = make_project(env.root, {"pulse": "raise ValueError('bad import')\n"})
    with pytest.raises(SpecError) as raised:
        load_spec("pulse", tool_file=tool_file, build_parser=None)
    assert "bad import" in raised.value.message


def test_reference_script_without_a_parser_raises(env):
    tool_file = make_project(env.root, {"pulse": "def main(argv):\n    return 0\n"})
    with pytest.raises(SpecError):
        load_spec("pulse", tool_file=tool_file, build_parser=None)


def test_real_reference_forms_load_without_env():
    for command in ("pulse", "ct", "carve", "phish", "ioc", "chroma", "urlscan"):
        assert load_spec(command, tool_file=SCANNER_FILE, build_parser=None).options, (
            command
        )


# --------------------------------------------------------------------------------------
# 3.6 render_argv (spec 12.2 vectors) and the picker-facing helpers
# --------------------------------------------------------------------------------------

SCAN_RENDER = [
    (
        {
            "PORTS": "80,443",
            "INTEL": "true",
            "DRY_RUN": "false",
            "HEADER": "'X-A: 1' 'X-B: 2'",
            "METHOD": "HEAD",
            "TARGETS": "127.0.0.1 10.0.0.1",
        },
        [],
        [
            "--ports",
            "80,443",
            "--intel",
            "--method",
            "HEAD",
            "--header",
            "X-A: 1",
            "--header",
            "X-B: 2",
            "127.0.0.1",
            "10.0.0.1",
        ],
    ),
    ({"PORTS": "80"}, ["--ports", "443", "h"], ["--ports", "443", "h"]),
    ({"PORTS": "80"}, ["--ports=443", "h"], ["--ports=443", "h"]),
    ({"TARGETS": "a b"}, ["h"], ["h"]),
    ({"TARGETS": "a b"}, [], ["a", "b"]),
    ({"PATHS": "-x"}, [], ["--paths=-x"]),
    ({"AUTHORIZED": "true"}, [], ["--authorized"]),
    ({"AUTHORIZED": "true"}, ["--i-own-this"], ["--i-own-this"]),
    (
        {"COMMON": "yes", "DELAY": "0.4-1.2"},
        ["h"],
        ["--common", "--delay", "0.4-1.2", "h"],
    ),
    ({}, ["h", "--ports", "80"], ["h", "--ports", "80"]),
    ({"PORTS": "80"}, [], ["--ports", "80"]),
    # bool switches: only 1/true/yes/on (any case) pass the flag
    ({"INTEL": "TRUE"}, [], ["--intel"]),
    ({"INTEL": "On"}, [], ["--intel"]),
    ({"INTEL": "1"}, [], ["--intel"]),
    ({"INTEL": "no"}, [], []),
    ({"INTEL": "0"}, [], []),
    ({"INTEL": "banana"}, [], []),
    # a bool already on the command line is not repeated
    ({"INTEL": "true"}, ["--intel", "h"], ["--intel", "h"]),
    # a value option consumes the next token; a switch does not
    ({"TARGETS": "a"}, ["--dry-run", "h"], ["--dry-run", "h"]),
    ({"TARGETS": "a"}, ["--ports", "80"], ["--ports", "80", "a"]),
    # exact matching only: no argparse abbreviation, no stacked short flags
    ({"PORTS": "80"}, ["--por", "443"], ["--ports", "80", "--por", "443"]),
    (
        {"TARGETS_FILE": "saved.txt"},
        ["-lx.txt"],
        ["--targets-file", "saved.txt", "-lx.txt"],
    ),
    # a short spelling in argv counts as the option being supplied
    ({"TARGETS_FILE": "saved.txt"}, ["-l", "x.txt"], ["-l", "x.txt"]),
    # after `--` everything fills positionals
    ({"TARGETS": "a b"}, ["--", "h"], ["--", "h"]),
    # values that look like flags use the = form; empty saved values are still emitted
    ({"HEADER": "-weird"}, [], ["--header=-weird"]),
]


@pytest.mark.parametrize("settings,argv,expected", SCAN_RENDER)
def test_render_argv_scan_vectors(settings, argv, expected):
    assert render_argv(scan_spec(), settings, list(argv)) == expected


def test_render_argv_does_not_mutate_its_inputs():
    argv, settings = ["h"], {"PORTS": "80"}
    render_argv(scan_spec(), settings, argv)
    assert argv == ["h"] and settings == {"PORTS": "80"}


def test_render_argv_orders_leading_flags_argv_positionals_tail():
    spec = Spec(
        options=(
            option("COMMAND", "positional", choices=["go"]),
            option("FLAG", "value", ["--flag"]),
            option("TARGET", "positional"),
            option("EXTRA", "tail", repeatable=True),
        ),
        subcommands=(("go", ""),),
        command_name="COMMAND",
    )
    saved = {"COMMAND": "go", "FLAG": "f", "TARGET": "t", "EXTRA": "-I --opt 'a b'"}
    assert render_argv(spec, saved, ["mid"]) == [
        "go",
        "--flag",
        "f",
        "mid",
        "-I",
        "--opt",
        "a b",
    ]


def test_render_argv_store_false_is_inverted():
    spec = Spec(
        options=(option("NOISE", "bool", ["--no-noise", "--quiet"], store_false=True),),
        subcommands=(),
        command_name="",
    )
    assert render_argv(spec, {"NOISE": "true"}, []) == []
    assert render_argv(spec, {"NOISE": "false"}, []) == ["--no-noise"]
    assert render_argv(spec, {"NOISE": "anything"}, []) == ["--no-noise"]


def test_render_argv_picks_the_first_long_flag_else_the_first_flag():
    spec = Spec(
        options=(
            option("LONGISH", "bool", ["-l", "--long", "--longer"]),
            option("SHORT", "value", ["-s"]),
        ),
        subcommands=(),
        command_name="",
    )
    assert render_argv(spec, {"LONGISH": "true", "SHORT": "v"}, []) == [
        "--long",
        "-s",
        "v",
    ]


def test_render_argv_option_without_a_flag_emits_bare_parts():
    spec = Spec(
        options=(option("LOOSE", "value", []),), subcommands=(), command_name=""
    )
    assert render_argv(spec, {"LOOSE": "a b"}, []) == ["a b"]


def test_render_argv_repeatable_value_repeats_the_flag_per_part():
    spec = Spec(
        options=(option("HEADER", "value", ["--header"], repeatable=True),),
        subcommands=(),
        command_name="",
    )
    assert render_argv(spec, {"HEADER": "'a b' c"}, []) == [
        "--header",
        "a b",
        "--header",
        "c",
    ]


def test_render_argv_positional_with_choices_only_takes_a_matching_token():
    spec = Spec(
        options=(
            option("MODE", "positional", choices=["fast", "slow"]),
            option("NAME", "positional"),
        ),
        subcommands=(),
        command_name="",
    )
    # `Fast` matches MODE case-insensitively, so MODE is provided; `xyz` then fills NAME
    assert render_argv(spec, {"MODE": "slow", "NAME": "n"}, ["Fast", "xyz"]) == [
        "Fast",
        "xyz",
    ]
    # `xyz` is not a MODE choice and is skipped for MODE, so the saved MODE is still emitted
    # (saved positionals are appended AFTER the explicit argv)
    assert render_argv(spec, {"MODE": "slow"}, ["xyz"]) == ["xyz", "slow"]


POLICY_RENDER = [
    (
        {"COMMAND": "check", "OPERATION": "manual"},
        [],
        ["check", "--operation", "manual"],
    ),
    # the subcommand typed in argv wins; options scoped to the saved subcommand are dropped
    ({"COMMAND": "check", "OPERATION": "manual"}, ["status"], ["status"]),
    ({"COMMAND": "check"}, ["status"], ["status"]),
    (
        {"OPERATION": "manual"},
        [],
        [],
    ),  # no active subcommand: check-scoped options are invisible
]


@pytest.mark.parametrize("settings,argv,expected", POLICY_RENDER)
def test_render_argv_subcommand_vectors(settings, argv, expected):
    assert render_argv(policy_spec(), settings, list(argv)) == expected


def test_render_argv_scans_for_the_subcommand_only_before_double_dash():
    spec = policy_spec()
    # `check` after `--` is not read as the subcommand, so the saved `status` stays active and the
    # check-scoped OPERATION is invisible, and the saved COMMAND stays in the rendered arguments.
    assert render_argv(
        spec, {"COMMAND": "status", "OPERATION": "x"}, ["--", "check"]
    ) == ["status", "--", "check"]


def test_picker_helper_true_set():
    assert options._TRUE == {"1", "true", "yes", "on"}


def test_picker_helpers_visible_and_active_command():
    spec = policy_spec()
    assert options._active_command(spec, {}) is None
    assert options._active_command(spec, {"COMMAND": "check"}) == "check"
    assert options._active_command(spec, {"COMMAND": ""}) is None
    assert (
        options._active_command(scan_spec(), {"COMMAND": "check"}) is None
    )  # no subparsers
    everything = options._visible(spec, None)
    scoped = options._visible(spec, "check")
    assert all(o.subcommand == "" for o in everything)
    assert {o.subcommand for o in scoped} == {"", "check"}
    assert options._visible(scan_spec(), None) == list(scan_spec().options)


# --------------------------------------------------------------------------------------
# 3.5 console option operations
# --------------------------------------------------------------------------------------


def _set(settings, key, value, tokens=None, name="scan"):
    return options.set_option(
        name,
        settings,
        key,
        value,
        tool_file=SCANNER_FILE,
        build_parser=BUILD_PARSER,
        tokens=tokens,
    )


SET_VECTORS = [
    ("ports", "80,443", None, True, "PORTS", "80,443"),
    ("PORT-RANGE", "1-5", None, True, "PORT_RANGE", "1-5"),
    ("port_range", "1-5", None, True, "PORT_RANGE", "1-5"),
    ("intel", "YES", None, True, "INTEL", "true"),
    ("intel", "on", None, True, "INTEL", "true"),
    ("intel", "1", None, True, "INTEL", "true"),
    ("intel", "No", None, True, "INTEL", "false"),
    ("intel", "OFF", None, True, "INTEL", "false"),
    ("intel", "0", None, True, "INTEL", "false"),
    ("method", "head", None, True, "METHOD", "HEAD"),
    ("method", "Post", None, True, "METHOD", "POST"),
    ("header", "X-A: 1", ["X-A: 1"], True, "HEADER", "'X-A: 1'"),
    ("header", "a b", ["a", "b"], True, "HEADER", "a b"),
    ("targets", "a b c", ["a", "b", "c"], True, "TARGETS", "a b c"),
    ("targets", "a b c", None, True, "TARGETS", "a b c"),
    ("targets", "'a b' c", None, True, "TARGETS", "'a b' c"),
    ("authorized", "on", None, True, "AUTHORIZED", "true"),
]


@pytest.mark.parametrize("key,value,tokens,ok,stored_name,stored", SET_VECTORS)
def test_set_option_success_vectors(env, key, value, tokens, ok, stored_name, stored):
    settings = {}
    assert _set(settings, key, value, tokens) is ok
    assert settings == {stored_name: stored}
    assert f"{stored_name} => {stored}" in env.rich_text


@pytest.mark.parametrize(
    "key,value",
    [("intel", "maybe"), ("method", "patch"), ("method", ""), ("nope", "1"), ("", "x")],
)
def test_set_option_failure_vectors_store_nothing(env, key, value):
    settings = {}
    assert _set(settings, key, value) is False
    assert settings == {}
    assert env.rich_text.strip()


def test_set_option_bool_error_names_the_option_and_the_valid_answers(env):
    _set({}, "intel", "maybe")
    assert (
        "INTEL" in env.rich_text
        and "true" in env.rich_text
        and "false" in env.rich_text
    )


def test_set_option_unknown_key_hint_names_the_key(env):
    _set({}, "nopeoption", "1")
    assert "nopeoption" in env.rich_text


def test_set_option_choices_error_lists_the_allowed_values(env):
    _set({}, "method", "patch")
    assert "GET, HEAD, OPTIONS, POST" in env.rich_text


def test_set_option_echo_escapes_markup_in_values(env):
    settings = {}
    assert _set(settings, "paths", "[bold]x[/bold]") is True
    assert "PATHS => [bold]x[/bold]" in env.rich_text


def test_set_option_overwrites_an_existing_value(env):
    settings = {"PORTS": "1"}
    assert _set(settings, "ports", "2") is True
    assert settings == {"PORTS": "2"}


def test_set_option_spec_error_prints_and_fails(env, monkeypatch):
    monkeypatch.setattr(options, "DISABLED_REFERENCES", frozenset({"skiff"}))
    settings = {}
    assert (
        options.set_option(
            "skiff", settings, "x", "1", tool_file=SCANNER_FILE, build_parser=None
        )
        is False
    )
    assert "disabled" in env.rich_text
    assert settings == {}


def test_set_option_for_scan_without_a_parser_fails(env):
    assert (
        options.set_option(
            "scan", {}, "ports", "1", tool_file=SCANNER_FILE, build_parser=None
        )
        is False
    )
    assert env.rich_text.strip()


def test_set_option_subcommand_scoping(env):
    settings = {}
    # FILE exists under several subcommands: ambiguous until a command is chosen
    assert (
        options.set_option(
            "policy",
            settings,
            "file",
            "p.json",
            tool_file=SCANNER_FILE,
            build_parser=None,
        )
        is False
    )
    assert "COMMAND" in env.rich_text
    assert settings == {}
    assert (
        options.set_option(
            "policy",
            settings,
            "command",
            "import",
            tool_file=SCANNER_FILE,
            build_parser=None,
        )
        is True
    )
    assert (
        options.set_option(
            "policy",
            settings,
            "file",
            "p.json",
            tool_file=SCANNER_FILE,
            build_parser=None,
        )
        is True
    )
    assert settings == {"COMMAND": "import", "FILE": "p.json"}


def test_set_option_tail_options_store_a_shell_joined_value(env, monkeypatch):
    spec = Spec(
        options=(option("EXTRA", "tail", repeatable=True),),
        subcommands=(),
        command_name="",
    )
    monkeypatch.setattr(options, "load_spec", lambda *args, **kwargs: spec)
    settings = {}
    assert (
        options.set_option(
            "x",
            settings,
            "extra",
            "ignored",
            tool_file=SCANNER_FILE,
            build_parser=None,
            tokens=["-I", "a b"],
        )
        is True
    )
    assert settings == {"EXTRA": "-I 'a b'"}


def test_unset_option_removes_a_saved_key_case_and_dash_insensitively(env):
    settings = {"PORT_RANGE": "1-5", "PORTS": "80"}
    options.unset_option(settings, "port-range")
    assert settings == {"PORTS": "80"}
    assert "PORT_RANGE" in env.rich_text


def test_unset_option_reports_a_key_that_is_not_set(env):
    settings = {"PORTS": "80"}
    options.unset_option(settings, "zzz")
    assert settings == {"PORTS": "80"}
    assert "zzz is not set" in env.rich_text


@pytest.mark.parametrize("word", ["all", "ALL", "All", "*"])
def test_unset_all_clears_every_saved_option(env, word):
    settings = {"PORTS": "80", "INTEL": "true"}
    options.unset_option(settings, word)
    assert settings == {}
    assert env.rich_text.strip()


def test_print_settings_when_empty_names_the_module(env):
    options.print_settings("pulse", {})
    assert "pulse" in env.rich_text


def test_print_settings_lists_sorted_name_arrow_value_lines(env):
    options.print_settings("scan", {"PORTS": "80", "INTEL": "true", "DELAY": "[x]"})
    lines = [line.rstrip() for line in env.rich_text.splitlines() if line.strip()]
    assert lines == ["DELAY => [x]", "INTEL => true", "PORTS => 80"]


def test_prepare_argv_without_settings_copies_argv_and_never_loads_a_spec(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("no spec load without saved settings")

    monkeypatch.setattr(options, "load_spec", boom)
    argv = ["a", "b"]
    result = options.prepare_argv(
        "scan", argv, {}, tool_file=SCANNER_FILE, build_parser=BUILD_PARSER
    )
    assert result == ["a", "b"] and result is not argv


def test_prepare_argv_applies_saved_settings(env):
    merged = options.prepare_argv(
        "scan",
        ["h"],
        {"PORTS": "80"},
        tool_file=SCANNER_FILE,
        build_parser=BUILD_PARSER,
    )
    assert merged == ["--ports", "80", "h"]


def test_prepare_argv_warns_and_passes_argv_through_on_spec_error(env, monkeypatch):
    monkeypatch.setattr(options, "DISABLED_REFERENCES", frozenset({"skiff"}))
    merged = options.prepare_argv(
        "skiff", ["a"], {"X": "1"}, tool_file=SCANNER_FILE, build_parser=None
    )
    assert merged == ["a"]
    assert "disabled" in env.rich_text


def test_show_options_spec_error_prints_the_message(env, monkeypatch):
    monkeypatch.setattr(options, "DISABLED_REFERENCES", frozenset({"tcurl"}))
    options.show_options("tcurl", {}, tool_file=SCANNER_FILE, build_parser=None)
    assert "disabled" in env.rich_text


def test_show_options_table_for_scan(env):
    options.show_options(
        "scan", {"PORTS": "80,443"}, tool_file=SCANNER_FILE, build_parser=BUILD_PARSER
    )
    text = env.rich_text
    header = next(
        line for line in text.splitlines() if "Name" in line and "Value" in line
    )
    assert all(word in header for word in ("Name", "Value", "Required", "Description"))
    assert "scan options" in text
    rows = {
        line.split()[0]: line
        for line in text.splitlines()
        if line.strip() and line.split()[0].isupper()
    }
    assert len(rows) >= 55
    assert "80,443" in rows["PORTS"]
    assert (
        "(GET, HEAD, OPTIONS, POST)" in rows["METHOD"] and "--method" in rows["METHOD"]
    )
    assert "GET" in rows["METHOD"]  # the default note, shown when no value is saved
    assert "·" in rows["DRY_RUN"]  # no value and no default -> placeholder
    assert "no" in rows["PORTS"].split()  # Required column
    assert "--authorized, --i-own-this" in rows["AUTHORIZED"]


def test_show_options_ends_with_a_hint_about_set_and_run(env):
    options.show_options("scan", {}, tool_file=SCANNER_FILE, build_parser=BUILD_PARSER)
    last_line = [line for line in env.rich_text.splitlines() if line.strip()][-1]
    assert "set" in last_line and "run" in last_line


def test_show_options_without_an_active_subcommand_lists_subcommands_and_the_command_option(
    env,
):
    options.show_options("policy", {}, tool_file=SCANNER_FILE, build_parser=None)
    text = env.rich_text
    for sub in ("check", "example", "import", "status", "validate"):
        assert sub in text
    assert "COMMAND" in text
    assert (
        "--callback-domain" not in text
    )  # check-scoped flags are hidden until a command is set


def test_show_options_with_an_active_subcommand_shows_only_its_options(env):
    options.show_options(
        "policy", {"COMMAND": "check"}, tool_file=SCANNER_FILE, build_parser=None
    )
    text = env.rich_text
    assert "--operation" in text
    assert "--callback-domain" in text
