"""The `bughunt` command line: decide what a set of words means, then do it.

A bare target or scan flag keeps meaning "scan". Everything else is a reserved word: a built-in
command, a module (or alias), a phase title, or a near-miss of one of those, which is refused with a
suggestion instead of being quietly scanned as a host name.
"""

from __future__ import annotations

import difflib
import json
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NamedTuple

from rich.markup import escape
from rich.table import Table
from rich.text import Text

from bughunt import VERSION
from bughunt.console import catalog, ui
from bughunt.core import ledger, termio
from bughunt.core import route as route_gate
from bughunt.modules import MODULES

_ROUTED_WORDS = (
    "scan",
    "console",
    "modules",
    "commands",
    "catalog",
    "guide",
    "doctor",
    "setup",
    "examples",
    "completion",
    "pipeline",
    "chain",
    "schema",
)
_COMMAND_WORDS = (*_ROUTED_WORDS, "version", "help")
_HELP_FLAGS = ("-h", "--help")

_USAGE = {
    "scan": "bughunt scan <target> [flags]    (bughunt scan --help lists every flag)",
    "console": "bughunt console [--text]",
    "modules": "bughunt modules [phase]",
    "catalog": "bughunt catalog [--compact]",
    "guide": "bughunt guide",
    "doctor": "bughunt doctor",
    "setup": "bughunt setup [--venv DIR] [--no-venv] [--browser] [--no-workspace]",
    "examples": "bughunt examples",
    "completion": "bughunt completion bash|zsh",
    "version": "bughunt version",
    "help": "bughunt help [command | module]",
}


class Route(NamedTuple):
    """What a command line means: a handler name, its remaining words, and how it was spelled."""

    command: str
    args: list
    scan_verb: bool = False
    token: str = ""
    suggestion: str = ""


@dataclass(frozen=True)
class _Context:
    tool_file: Path
    scan_main: Callable
    build_parser: Callable | None


# --------------------------------------------------------------------------------------
# routing
# --------------------------------------------------------------------------------------


def _suggestion_pool() -> dict[str, str]:
    """Typo candidates, each mapped to the command that would actually run."""
    pool = {word: word for word in _COMMAND_WORDS}
    pool["commands"] = "modules"
    pool.update((name, name) for name in MODULES)
    pool.update((tool.command, tool.command) for tool in catalog.REFERENCES)
    pool.update((title.lower(), title.lower()) for title in catalog.group_names())
    return pool


_SUGGESTION_POOL = _suggestion_pool()


def suggest_command(token: str) -> str | None:
    """The command a near-miss word was probably meant to be, or None when it looks like a host."""
    if not token or token.startswith("-") or token.isdigit():
        return None
    if any(mark in token for mark in ".:/"):
        return None
    best = difflib.get_close_matches(token, list(_SUGGESTION_POOL), n=1, cutoff=0.8)
    if not best or best[0] == token:
        return None
    return _SUGGESTION_POOL[best[0]]


def _route_phase(title: str, rest: list[str]) -> Route:
    if not rest or rest[0] in _HELP_FLAGS:
        return Route("phase", [], token=title)
    follow = rest[0]
    if follow == "scan":
        return Route("scan", rest[1:], scan_verb=True, token="scan")
    module = catalog.reference_canonical(follow)
    if module is not None:
        return Route("module", rest[1:], token=module)
    return Route("phase-unknown", [follow], token=title)


def route_argv(argv: list[str]) -> Route:
    words = list(argv)
    if not words:
        return Route("help-usage", [])
    head, rest = words[0], words[1:]
    if head == "--":
        return Route("scan", rest)
    if head in ("-h", "--help", "help"):
        return Route("help", rest)
    if head in ("-V", "--version", "version"):
        return Route("version", rest)
    if head in _ROUTED_WORDS:
        return Route(
            "modules" if head == "commands" else head,
            rest,
            scan_verb=head == "scan",
            token=head,
        )
    if catalog.reference_canonical(head) is not None:
        return Route("module", rest, token=head)
    phase = catalog.match_group(head)
    if phase is not None:
        return _route_phase(phase, rest)
    suggestion = suggest_command(head)
    if suggestion is not None:
        return Route("suggest", rest, token=head, suggestion=suggestion)
    return Route("scan", words)


# --------------------------------------------------------------------------------------
# small output helpers
# --------------------------------------------------------------------------------------


def _safe(untrusted: str) -> str:
    """Untrusted text, made printable: control characters shown as escapes, markup brackets escaped."""
    return escape(termio.neutralize(untrusted))


def _line(text: str = "", style: str | None = None) -> None:
    ui.console.print(Text(termio.neutralize(text, keep_lines=True), style=style or ""))


def _long_line(text: str, style: str | None = None) -> None:
    """A line that must never be wrapped, such as a path someone will copy."""
    ui.console.print(
        Text(termio.neutralize(text, keep_lines=True), style=style or ""),
        soft_wrap=True,
    )


def _two_columns(rows, *, indent: str = "  ") -> None:
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2, 0, 0))
    table.add_column(no_wrap=True)
    table.add_column()
    for left, right in rows:
        table.add_row(
            Text(termio.neutralize(indent + left, keep_lines=True), style="info"),
            Text(termio.neutralize(right, keep_lines=True)),
        )
    ui.console.print(table)


def _wants_help(args: list[str]) -> bool:
    return bool(args) and args[0] in _HELP_FLAGS


def _print_blurb(topic: str) -> None:
    _line(catalog.BUILTIN_SUMMARIES[topic])
    _line("Usage: " + _USAGE[topic], "muted")


def _exit_status(request: SystemExit) -> int:
    code = request.code
    if code is None:
        return 0
    return code if isinstance(code, int) else 1


def _run_scan(args: list[str], prog: str, ctx: _Context) -> int:
    try:
        return ctx.scan_main(args, prog=prog)
    except SystemExit as request:
        return _exit_status(request)


# --------------------------------------------------------------------------------------
# overview, examples, guide
# --------------------------------------------------------------------------------------


def print_overview() -> None:
    ui.console.print(
        Text.assemble(
            (f"Bughunt {VERSION}", "brand"), "  authorized HTTP attack-surface toolkit"
        )
    )
    _line()
    _line("Get going", "bold")
    _two_columns(
        (
            ("bughunt console", "open the interactive console (type help inside it)"),
            ("bughunt guide", "see what to do next, from where you are"),
            (
                "bughunt scan <target>",
                "map a host, URL or CIDR range you are authorized to test",
            ),
        )
    )
    _line()
    _line("Commands", "bold")
    _two_columns(catalog.BUILTIN_SUMMARIES.items())
    _line()
    _line("Phases of a hunt (bughunt <phase> lists the modules in one)", "bold")
    _two_columns(
        (title, catalog.phase_purpose(title)) for title in catalog.group_names()
    )
    _line()
    _line("Flags you will reach for with scan", "bold")
    _line("  --ports 80,443   --common   --dry-run   -l FILE   --json FILE")
    _line("A bare target or flag scans: bughunt 127.0.0.1 --dry-run", "muted")


def print_examples() -> int:
    groups = (
        (
            "Set up an engagement",
            (
                ("bughunt scope init", "create the workspace and scope file"),
                ("bughunt scope add app.example.test", "put a host in scope"),
                ("bughunt policy example", "print a sample mission policy"),
                ("bughunt policy status", "see whether a verified policy is loaded"),
            ),
        ),
        (
            "Look around",
            (
                (
                    "bughunt scan 127.0.0.1 --ports 80,8080 --dry-run",
                    "show what a scan would do",
                ),
                ("bughunt dns app.example.test", "resolve an in-scope name"),
                ("bughunt pulse urls.txt", "check which listed URLs answer"),
                ("bughunt recon", "list the recon modules"),
            ),
        ),
        (
            "Work interactively",
            (
                ("bughunt console", "pick a module, set options, run it"),
                ("bughunt completion bash", "print a completion script for your shell"),
                (
                    "bughunt catalog --compact",
                    "machine-readable catalog for other front-ends",
                ),
            ),
        ),
    )
    for heading, rows in groups:
        _line(heading, "bold")
        _two_columns(rows)
        _line()
    return 0


def _print_guide() -> None:
    from bughunt.console import guide as walkthrough

    _line("Where to go next, in order:", "bold")
    for number, step in enumerate(walkthrough.plan(), start=1):
        if step.ready:
            marker = Text("[ready]", style="ok")
        else:
            marker = Text(f"[blocked: {step.blocked_reason}]", style="warn")
        ui.console.print(
            Text.assemble(f"{number}. ", (step.module, "info"), "  ", marker)
        )
        _line("   " + step.why, "muted")
        follow = [module for module, _why in walkthrough.follow_ons(step.module)]
        if follow:
            _line("   then: " + ", ".join(follow), "muted")


def _print_module_topic(token: str, ctx: _Context) -> None:
    from bughunt.console.console import _module_facts

    canonical = catalog.reference_canonical(token)
    summary, aliases, is_reference = _module_facts(canonical)
    ui.console.print(Text.assemble((canonical, "info"), "  ", summary))
    _line(
        f"Run it:     bughunt {canonical} [args]     or     bughunt {canonical} --help"
    )
    _line(f"In console: use {canonical}, then show options, set NAME VALUE, run [args]")
    if aliases:
        _line("Also known as: " + ", ".join(aliases))
    if not is_reference:
        return
    tool = catalog.tool_by_command(canonical)
    located = catalog.locate_script(tool, ctx.tool_file)
    if located is not None:
        _long_line(f"Program: {located}")
    else:
        _line(f"Program not on disk: looked for {tool.folder}/{tool.script}.", "warn")
        _line("Point BUGHUNT_ADDONS at the folder that holds it.", "muted")


# --------------------------------------------------------------------------------------
# shell completion scripts
# --------------------------------------------------------------------------------------


def _completion_vocabulary(build_parser) -> dict:
    commands = [
        *_COMMAND_WORDS,
        *(title.lower() for title in catalog.group_names()),
        *MODULES,
    ]
    for tool in catalog.REFERENCES:
        commands.append(tool.command)
    for tool in catalog.REFERENCES:
        commands.extend(tool.aliases)
    parser = build_parser("bughunt") if build_parser is not None else None
    flags = [
        flag
        for action in getattr(parser, "_actions", ())
        for flag in action.option_strings
    ]
    return {"commands": commands, "flags": flags, "groups": catalog.group_names()}


def _phase_branches(indent: str, action: str) -> str:
    """One `case` arm per phase; ``action`` receives the space-separated member list."""
    arms = []
    for title, members in catalog.MODULE_GROUPS:
        arms.append(f"{indent}{title.lower()}) {action.format(' '.join(members))} ;;")
    return "\n".join(arms)


def _bash_script(vocabulary: dict) -> str:
    arms = _phase_branches("            ", 'candidates="{}"')
    return f"""# bash completion for bughunt {VERSION}
# install: eval "$(bughunt completion bash)"   (or save the output of bughunt completion bash and source it)
_bughunt_complete() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    local first="${{COMP_WORDS[1]}}"
    local candidates=""
    COMPREPLY=()
    if [[ "$cur" == -* ]]; then
        candidates="{" ".join(vocabulary["flags"])}"
    elif (( COMP_CWORD == 1 )); then
        candidates="{" ".join(vocabulary["commands"])}"
    elif (( COMP_CWORD == 2 )); then
        case "$first" in
            modules|commands) candidates="{" ".join(vocabulary["groups"])}" ;;
            completion) candidates="bash zsh" ;;
{arms}
            *) COMPREPLY=( $(compgen -f -- "$cur") ); return 0 ;;
        esac
    else
        COMPREPLY=( $(compgen -f -- "$cur") )
        return 0
    fi
    COMPREPLY=( $(compgen -W "$candidates" -- "$cur") )
}}
complete -F _bughunt_complete bughunt
"""


def _zsh_script(vocabulary: dict) -> str:
    arms = _phase_branches("            ", "compadd {}")
    return f"""#compdef bughunt
# zsh completion for bughunt {VERSION}
# install: bughunt completion zsh > "${{fpath[1]}}/_bughunt"   then start a new shell
local -a command_words flag_words group_words
command_words=({" ".join(vocabulary["commands"])})
flag_words=({" ".join(vocabulary["flags"])})
group_words=({" ".join(vocabulary["groups"])})
case $CURRENT in
    2)
        if [[ $words[2] == -* ]]; then
            compadd -a flag_words
        else
            compadd -a command_words
        fi ;;
    3)
        case $words[2] in
            modules|commands) compadd -a group_words ;;
            completion) compadd bash zsh ;;
{arms}
            *) if [[ $words[3] == -* ]]; then compadd -a flag_words; else _files; fi ;;
        esac ;;
    *)
        if [[ $words[CURRENT] == -* ]]; then
            compadd -a flag_words
        else
            _files
        fi ;;
esac
"""


_SCRIPT_WRITERS = {"bash": _bash_script, "zsh": _zsh_script}


def print_completion(shell: str, build_parser) -> int:
    writer = _SCRIPT_WRITERS.get(shell)
    if writer is None:
        ui.console.print("[err]completion needs one of: bash, zsh[/err]")
        _line("Usage: " + _USAGE["completion"], "muted")
        return 2
    sys.stdout.write(writer(_completion_vocabulary(build_parser)))
    return 0


# --------------------------------------------------------------------------------------
# command handlers: (route, context) -> exit code
# --------------------------------------------------------------------------------------


def _cmd_usage(_route: Route, _ctx: _Context) -> int:
    print_overview()
    _line()
    ui.console.print("[err]No command or target was given.[/err]")
    return 2


def _cmd_help(route: Route, ctx: _Context) -> int:
    topic = route.args[0] if route.args else ""
    if topic == "commands":
        topic = "modules"
    if topic == "scan":
        return _run_scan(["--help"], "bughunt scan", ctx)
    if topic in ("", *_HELP_FLAGS):
        print_overview()
        return 0
    if topic in catalog.BUILTIN_SUMMARIES:
        _print_blurb(topic)
        return 0
    if catalog.reference_canonical(topic) is not None:
        _print_module_topic(topic, ctx)
        return 0
    ui.console.print(f"[err]No help topic for {_safe(topic)}.[/err]")
    _line(
        "Try bughunt help for the overview, or bughunt scan --help for scan flags.",
        "muted",
    )
    return 2


def _cmd_version(_route: Route, _ctx: _Context) -> int:
    print("Bughunt " + VERSION)
    return 0


def _print_module_footer(tool_file: Path) -> None:
    _line()
    _line("Interactive:  bughunt console    then   use <module>, set NAME VALUE, run")
    _line(
        "One-shot:      bughunt <module> [args]    for example   bughunt dns app.example.test"
    )
    _line()
    _line("Reference tools are looked up in these folders, first match wins:")
    for root in catalog.addon_roots(tool_file):
        _long_line(f"  {root}")
    present = [
        (tool.command, path)
        for tool in catalog.REFERENCES
        if (path := catalog.locate_script(tool, tool_file)) is not None
    ]
    if present:
        _line()
        _line("Module files:")
        for command, path in present:
            _long_line(f"  {command:<9}{path}")
    _line()
    _line(
        "To scan a host named like a command: bughunt scan <host>   or   bughunt -- <host>",
        "muted",
    )


def _cmd_modules(route: Route, ctx: _Context) -> int:
    from bughunt.console.console import print_loadable

    if _wants_help(route.args):
        _print_blurb("modules")
        return 0
    if len(route.args) > 1:
        ui.console.print("[err]modules takes one group name.[/err]")
        return 2
    group = route.args[0] if route.args else None
    if not print_loadable(ctx.tool_file, group, guide=False):
        return 2
    if group is None:
        _print_module_footer(ctx.tool_file)
    return 0


def _cmd_catalog(route: Route, ctx: _Context) -> int:
    from bughunt.console.catalog_export import export_catalog

    if _wants_help(route.args):
        _print_blurb("catalog")
        return 0
    document = export_catalog(tool_file=ctx.tool_file, build_parser=ctx.build_parser)
    if route.args == ["--compact"]:
        print(json.dumps(document, separators=(",", ":")))
    else:
        print(json.dumps(document, indent=2))
    return 0


def _cmd_guide(route: Route, _ctx: _Context) -> int:
    if _wants_help(route.args):
        _print_blurb("guide")
    else:
        _print_guide()
    return 0


def _cmd_doctor(route: Route, ctx: _Context) -> int:
    from bughunt.console import doctor

    if _wants_help(route.args):
        _print_blurb("doctor")
        return 0
    return doctor.run(ctx.tool_file)


def _cmd_setup(route: Route, _ctx: _Context) -> int:
    from bughunt.console import setup

    if _wants_help(route.args):
        _print_blurb("setup")
        return 0
    return setup.run(route.args)


def _cmd_examples(route: Route, _ctx: _Context) -> int:
    if _wants_help(route.args):
        _print_blurb("examples")
        return 0
    return print_examples()


def _cmd_completion(route: Route, ctx: _Context) -> int:
    if _wants_help(route.args):
        _print_blurb("completion")
        return 0
    return print_completion(route.args[0] if route.args else "", ctx.build_parser)


def _cmd_console(route: Route, ctx: _Context) -> int:
    if _wants_help(route.args):
        _print_blurb("console")
        return 0
    if route.args not in ([], ["--text"]):
        ui.console.print("[err]console takes no arguments except --text.[/err]")
        return 2
    return open_console(
        tool_file=ctx.tool_file,
        scan_main=ctx.scan_main,
        build_parser=ctx.build_parser,
        text=bool(route.args),
    )


def _cmd_module(route: Route, ctx: _Context) -> int:
    from bughunt.console import loader

    return loader.run_named(
        route.token, route.args, tool_file=ctx.tool_file, scan_main=ctx.scan_main
    )


def _cmd_suggest(route: Route, _ctx: _Context) -> int:
    guess = route.suggestion
    ui.console.print(
        f"[err]Unknown command {_safe(route.token)}.[/err] Did you mean [info]{_safe(guess)}[/info]?"
    )
    if catalog.reference_canonical(guess) is not None:
        _line(f"To run it: bughunt {guess} [args]")
    else:
        _line(f"To run it: bughunt {guess}")
    if route.args:
        _line("Arguments that were not forwarded: " + " ".join(route.args), "muted")
    _line(f"To scan a host called {route.token}: bughunt scan {route.token}")
    return 2


def _cmd_phase(route: Route, ctx: _Context) -> int:
    from bughunt.console.console import print_loadable

    print_loadable(ctx.tool_file, route.token, guide=False)
    return 0


def _cmd_phase_unknown(route: Route, ctx: _Context) -> int:
    from bughunt.console.console import print_loadable

    word = route.args[0]
    ui.console.print(
        f"[err]{_safe(word)} is not a module in {_safe(route.token)}.[/err]"
    )
    print_loadable(ctx.tool_file, route.token, guide=False)
    _line()
    _line(f"To scan a host called {word}: bughunt scan {word}")
    return 2


def _cmd_scan(route: Route, ctx: _Context) -> int:
    return _run_scan(route.args, "bughunt scan" if route.scan_verb else "bughunt", ctx)


def _cmd_structured(route: Route, _ctx: _Context) -> int:
    from bughunt.console import structured

    return structured.dispatch([route.command, *route.args])


_HANDLERS = {
    "help-usage": _cmd_usage,
    "help": _cmd_help,
    "version": _cmd_version,
    "modules": _cmd_modules,
    "catalog": _cmd_catalog,
    "guide": _cmd_guide,
    "doctor": _cmd_doctor,
    "setup": _cmd_setup,
    "examples": _cmd_examples,
    "completion": _cmd_completion,
    "console": _cmd_console,
    "module": _cmd_module,
    "suggest": _cmd_suggest,
    "phase": _cmd_phase,
    "phase-unknown": _cmd_phase_unknown,
    "scan": _cmd_scan,
    "pipeline": _cmd_structured,
    "chain": _cmd_structured,
    "schema": _cmd_structured,
}


# --------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------


def _terminal_attached() -> bool:
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        return False


def _deny_console(*lines: str) -> int:
    """Report why the console gate blocked; a failing output stream must never turn a denial into an open."""
    for line in lines:
        with suppress(Exception):
            _line(line, "red")
    return 2


def _console_route_policy():
    """Return (policy, exit_code). (None, None) means the gate is not active for the console."""
    path = route_gate.locate_config()
    if path is None:
        return None, None
    try:
        policy = route_gate.load_config(path)
    except route_gate.ConfigError as exc:
        return None, _deny_console(f"Route config invalid; console blocked: {exc}")
    if "console" not in policy.protect:
        return None, None
    return policy, None


def check_console_route(*, probe=None, resolver=None) -> int | None:
    """When a route config protects `console`, prove the tunnel is up before the console opens.

    Returns None to open, or a nonzero exit code to block. Fails closed: an invalid config, a probe error,
    a failed or missing verdict, or any unexpected exception blocks. No config means the gate is inactive.
    """
    if route_gate.optout_requested():
        try:
            route_gate.warn_optout("console")
        except Exception:
            return _deny_console(
                "Route opt-out audit could not be saved; console blocked."
            )
        return None
    try:
        policy, blocked_code = _console_route_policy()
        if blocked_code is not None or policy is None:
            return blocked_code
        extra = {"resolver": resolver} if resolver is not None else {}
        verdict = route_gate.verify(policy, kind="probe", probe=probe, **extra)
        if verdict is None or verdict.ok is not True:
            details = [str(line) for line in (verdict.details if verdict else ())]
            return _deny_console(*details, "Console blocked: the route check failed.")
    except Exception as exc:  # noqa: BLE001 - the route check must never escape as a pass or a crash
        return _deny_console(f"Route could not be verified; console blocked: {exc}")
    return None


def open_console(
    *,
    tool_file: Path,
    scan_main: Callable,
    build_parser,
    text: bool = False,
    probe=None,
    resolver=None,
) -> int:
    """The picker on a real terminal when it is installed; the typed console otherwise."""
    blocked_code = check_console_route(probe=probe, resolver=resolver)
    if blocked_code is not None:
        return blocked_code
    if not text and _terminal_attached():
        try:
            from bughunt.console.picker import run_picker
        except ImportError:
            pass
        else:
            return run_picker(
                tool_file=tool_file, scan_main=scan_main, build_parser=build_parser
            )
    from bughunt.console.console import run_console

    return run_console(
        tool_file=tool_file, scan_main=scan_main, build_parser=build_parser
    )


def _tolerate_unencodable_output() -> None:
    """A redirected stream on a non-UTF-8 locale (Windows cp1252) must not crash on glyphs such as the warning sign."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")


@ledger.sanitized
def dispatch(
    argv=None, *, scan_main, build_parser, tool_file, interactive: bool | None = None
) -> int:
    _tolerate_unencodable_output()
    words = list(sys.argv[1:] if argv is None else argv)
    if words[:1] == ["--json"]:
        from bughunt.console import structured

        return structured.dispatch(words[1:])
    if not words and (_terminal_attached() if interactive is None else interactive):
        return open_console(
            tool_file=tool_file, scan_main=scan_main, build_parser=build_parser
        )
    route = route_argv(words)
    ledger.CURRENT_TOOL.set(route.token or route.command)
    return _HANDLERS[route.command](route, _Context(tool_file, scan_main, build_parser))


def entry(argv=None) -> None:
    """Console-script target: run the scanner's main and leave through SystemExit."""
    from bughunt.core import scanner

    try:
        code = scanner.main(argv)
    except KeyboardInterrupt:
        code = 130
    raise SystemExit(code)
