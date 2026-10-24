"""The typed console: a prompt where you pick a module, save options for it, and run it.

``run_console`` owns the loop. The three collaborators it needs (the line reader, the module runner
and the option merger) can be injected, which is how the console is driven without a terminal.
"""

from __future__ import annotations

import os
import random
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from rich.table import Table
from rich.text import Text

from bughunt import VERSION
from bughunt.console import catalog, complete, loader, options, readiness, ui
from bughunt.console import guide as walkthrough
from bughunt.core import termio
from bughunt.modules import MODULES

BANNERS = (
    "\n".join(
        (
            "  .-----------------------------.",
            "  |  B U G H U N T              |",
            "  |  scope it. map it. prove it.|",
            "  '-----------------------------'",
        )
    ),
    "\n".join(
        (
            "      __",
            "  ___( o)>    scope first,",
            "  \\ <_. )     then traffic.",
            "   `---'",
        )
    ),
    "\n".join(
        (
            " o--[ scope ]--[ policy ]--[ traffic ]--[ evidence ]--o",
            "      only what you are authorized to touch",
        )
    ),
    "\n".join(
        (
            "    ,     ,",
            "   /(     )\\",
            "  ( /-----\\ )   bughunt",
            "   \\\\ o o //    authorized surface mapping",
            "    '-----'",
        )
    ),
    "\n".join(
        (
            "  (_)--.",
            "     '--> GET /",
            "  .-----'",
            " (_)--> 200 OK",
        )
    ),
)

_previous_banner = -1
_HISTORY_PAGE = 40
_SCAN_BLURB = catalog.BUILTIN_SUMMARIES["scan"]

_COMMAND_HELP = (
    ("show modules [phase]", "list the modules, grouped by hunt phase"),
    ("search <words>", "find a module by keyword"),
    ("use <module>", "select a module to work with"),
    ("show options", "the selected module's options and saved values"),
    ("set NAME VALUE", "save an option (NAME=VALUE works too)"),
    ("unset NAME | all", "forget one saved option, or every one"),
    ("run [args]", "run the selected module with your saved options"),
    ("<module> [args]", "run any module once; the selection stays put"),
    ("back", "deselect the module"),
    ("history, banner, version, doctor, examples", "housekeeping"),
    ("exit", "leave the console"),
)


# --------------------------------------------------------------------------------------
# facts about modules
# --------------------------------------------------------------------------------------


def _module_facts(name: str) -> tuple[str, tuple[str, ...], bool]:
    """(summary, aliases, is_reference_tool) for a canonical command name."""
    if name == "scan":
        return _SCAN_BLURB, (), False
    if name in MODULES:
        return MODULES[name], (), False
    tool = catalog.tool_by_command(name)
    if tool is not None:
        return tool.summary, tool.aliases, True
    return "", (), False


def canonical_module(token: str) -> str | None:
    return "scan" if token == "scan" else catalog.reference_canonical(token)


# --------------------------------------------------------------------------------------
# banner and listings
# --------------------------------------------------------------------------------------


def _choose_banner() -> str:
    global _previous_banner
    choices = [index for index in range(len(BANNERS)) if index != _previous_banner]
    _previous_banner = random.choice(choices)
    return BANNERS[_previous_banner]


def _print_art(art: str) -> None:
    widest = max(len(line) for line in art.splitlines())
    if ui.console.width >= widest + 2:
        ui.console.print(Text(art, style="brand"), soft_wrap=True)
    else:
        ui.console.print(Text("BUGHUNT", style="brand"))


def _print_readiness_line() -> None:
    next_module, message = readiness.gather().next_step()
    if next_module:
        ui.console.print(Text.assemble(("⚠ ", "warn"), message))
    else:
        ui.console.print(Text.assemble(("✓ ", "ok"), message))


def print_banner() -> None:
    _print_art(_choose_banner())
    ui.console.print(
        Text(
            f"Bughunt {VERSION}  authorized HTTP attack-surface toolkit", style="brand"
        )
    )
    ui.console.print(
        Text(
            "help  show modules  use <module>  set NAME VALUE  run  exit", style="muted"
        )
    )
    ui.console.print(
        Text(
            "snare keeps in-scope traffic while you browse; clutch lists what it saved.",
            style="muted",
        )
    )
    _print_readiness_line()


def _explain_unknown_group(token: str) -> None:
    owner = None
    module = canonical_module(token.strip())
    if module is not None:
        owner = catalog.group_for(module)
    if owner is not None:
        ui.console.print(
            Text(
                f"{token} is a module in the {owner} phase, not a phase name.",
                style="warn",
            )
        )
        return
    ui.console.print(Text(f"There is no phase called {token}.", style="warn"))
    ui.console.print(Text("Phases: " + ", ".join(catalog.group_names())))


def _member_notes(name: str, tool_file: Path) -> Text:
    summary, aliases, is_reference = _module_facts(name)
    cell = Text(summary)
    if aliases:
        cell.append("  also: " + ", ".join(aliases), style="muted")
    if (
        is_reference
        and catalog.locate_script(catalog.tool_by_command(name), tool_file) is None
    ):
        cell.append("  not on disk", style="warn")
    return cell


def _print_phase(title: str, state, tool_file: Path) -> None:
    heading = Text(title, style="bold")
    block = state.phase_block(title)
    if block:
        heading.append(f"  ⚠ {block}", style="warn")
    ui.console.print(heading)
    ui.console.print(Text("  " + catalog.phase_purpose(title), style="muted"))
    table = Table(
        box=None,
        show_header=False,
        show_edge=False,
        pad_edge=False,
        padding=(0, 2, 0, 0),
    )
    table.add_column(no_wrap=True)
    table.add_column()
    for name in dict(catalog.MODULE_GROUPS)[title]:
        table.add_row(Text("  " + name), _member_notes(name, tool_file))
    ui.console.print(table)


def _print_listing_hints() -> None:
    ui.console.print()
    ui.console.print(Text("Narrow it down:  show modules <phase>", style="muted"))
    ui.console.print(
        Text(
            "Pick one:        use <module>, then set NAME VALUE and run", style="muted"
        )
    )
    ui.console.print(
        Text(
            "Or just type a module name with its arguments; search <words> finds one by keyword.",
            style="muted",
        )
    )


def print_loadable(
    tool_file: Path, group: str | None = None, *, guide: bool = True
) -> bool:
    """List the modules, all phases or one. False when ``group`` names no phase."""
    state = readiness.gather()
    if group is None:
        titles = catalog.group_names()
    else:
        wanted = catalog.match_group(group)
        if wanted is None:
            _explain_unknown_group(group)
            return False
        titles = [wanted]
    for position, title in enumerate(titles):
        if position:
            ui.console.print()
        _print_phase(title, state, tool_file)
    if guide and group is None:
        _print_listing_hints()
    return True


# --------------------------------------------------------------------------------------
# the prompt
# --------------------------------------------------------------------------------------


def _stdout_is_terminal() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _prompt_in_color() -> bool:
    if "NO_COLOR" in os.environ:
        return False
    if os.environ.get("TERM", "") in ("", "dumb"):
        return False
    return _stdout_is_terminal()


def _paint(text: str, code: int, in_color: bool) -> str:
    # \x01 and \x02 tell readline the enclosed bytes take up no screen columns.
    return f"\x01\x1b[{code}m\x02{text}\x01\x1b[0m\x02" if in_color else text


def _prompt(active: str | None) -> str:
    from bughunt.modules import snare

    in_color = _prompt_in_color()
    pieces = [_paint("Bughunt", 35, in_color)]
    if active:
        pieces.append(_paint(active, 36, in_color))
    job = snare.job_tag()
    if job:
        pieces.append(_paint(f"[{job}]", 33, in_color))
    pieces.append(_paint(">", 32, in_color))
    return " ".join(pieces) + " "


def _background_printer(interactive: bool) -> Callable[[str], None]:
    """What snare calls to show a line while the prompt is waiting for input."""

    def show(line: str) -> None:
        if interactive:
            sys.stdout.write("\r\x1b[K")
        print(line, flush=True)
        if interactive:
            try:
                import readline

                readline.redisplay()
            except (ImportError, AttributeError):
                pass

    return show


# --------------------------------------------------------------------------------------
# one console session
# --------------------------------------------------------------------------------------


@dataclass
class _Session:
    tool_file: Path
    scan_main: Callable
    build_parser: Callable | None
    runner: Callable
    merger: Callable
    settings: dict[str, dict[str, str]]
    complete_state: complete.CompleteState
    transcript: list[str] = field(default_factory=list)
    active: str | None = None

    def say(self, line: str, style: str | None = None) -> None:
        ui.console.print(Text(line, style=style or ""))

    # -- leaving and help ---------------------------------------------------------------

    def leave(self, _rest: list[str]) -> bool:
        return True

    def show_help(self, _rest: list[str]) -> bool:
        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2, 0, 0))
        table.add_column(no_wrap=True)
        table.add_column()
        for command, meaning in _COMMAND_HELP:
            table.add_row(Text("  " + command, style="info"), Text(meaning))
        ui.console.print(table)
        self.say(
            "Tab completes commands, modules, option names and file names when the terminal supports it.",
            "muted",
        )
        if self.active:
            self.say(f"Selected module: {self.active}")
        return False

    def show_banner(self, _rest: list[str]) -> bool:
        print_banner()
        return False

    def show_version(self, _rest: list[str]) -> bool:
        ui.console.print(f"Bughunt {VERSION}")
        return False

    def run_doctor(self, _rest: list[str]) -> bool:
        from bughunt.console import doctor

        doctor.run(self.tool_file)
        return False

    def show_examples(self, _rest: list[str]) -> bool:
        from bughunt.console import cli

        cli.print_examples()
        return False

    # -- browsing -----------------------------------------------------------------------

    def search(self, rest: list[str]) -> bool:
        needle = " ".join(rest).lower()
        if not needle:
            self.say("Usage: search <words>", "muted")
            return False
        names = ["scan", *MODULES, *(tool.command for tool in catalog.REFERENCES)]
        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2, 0, 0))
        for column in range(3):
            table.add_column(no_wrap=column < 2)
        found = 0
        for name in names:
            summary, aliases, _is_reference = _module_facts(name)
            if any(needle in text.lower() for text in (name, summary, *aliases)):
                table.add_row(
                    Text(name),
                    Text(catalog.group_for(name) or "", style="muted"),
                    Text(summary),
                )
                found += 1
        if found:
            ui.console.print(table)
        else:
            self.say(
                f"Nothing matches {needle!r}. show modules lists everything.", "muted"
            )
        return False

    def show_history(self, _rest: list[str]) -> bool:
        if not self.transcript:
            self.say("Nothing typed yet.", "muted")
            return False
        recent = self.transcript[-_HISTORY_PAGE:]
        first_number = len(self.transcript) - len(recent) + 1
        for number, line in enumerate(recent, start=first_number):
            ui.console.print(Text.assemble((f"{number:>4}", "muted"), "  ", line))
        return False

    def list_modules(self, group_words: list[str]) -> None:
        if len(group_words) > 1:
            self.say("show modules takes one group name at most.", "warn")
            return
        print_loadable(self.tool_file, group_words[0] if group_words else None)

    def show(self, rest: list[str]) -> bool:
        topic = rest[0] if rest else "modules"
        if topic in ("modules", "module"):
            self.list_modules(rest[1:])
        elif topic == "options":
            self.show_active_options()
        else:
            self.say(
                f"Nothing to show for {topic}. Try show modules or show options.",
                "muted",
            )
        return False

    def modules(self, rest: list[str]) -> bool:
        self.list_modules(rest)
        return False

    def show_active_options(self) -> None:
        if self.active is None:
            self.say("Select a module first: use <module>", "muted")
            return
        options.show_options(
            self.active,
            self.settings.get(self.active, {}),
            tool_file=self.tool_file,
            build_parser=self.build_parser,
        )

    # -- selecting and configuring ------------------------------------------------------

    def use(self, rest: list[str]) -> bool:
        if len(rest) != 1:
            self.say("Usage: use <module>", "muted")
            return False
        module = canonical_module(rest[0])
        if module is None:
            self.explain_unknown_module(rest[0])
            return False
        self.active = module
        ui.console.print(Text.assemble(("Using ", "ok"), module))
        self.say("  " + catalog.module_when(module), "muted")
        return False

    def explain_unknown_module(self, token: str) -> None:
        from bughunt.console import cli

        guess = cli.suggest_command(token)
        if guess and canonical_module(guess):
            self.say(f"Unknown module {token}. Did you mean {guess}?", "warn")
        else:
            self.say(f"Unknown module {token}. show modules lists what exists.", "warn")

    def back(self, _rest: list[str]) -> bool:
        if self.active is None:
            self.say("No module is selected.", "muted")
        self.active = None
        return False

    def set_value(self, rest: list[str]) -> bool:
        if self.active is None:
            self.say("Select a module first: use <module>", "muted")
            return False
        saved = self.settings.setdefault(self.active, {})
        common = {"tool_file": self.tool_file, "build_parser": self.build_parser}
        if not rest:
            spec = self.complete_state.spec(self.active) if saved else None
            options.print_settings(self.active, saved, spec=spec)
        elif len(rest) == 1:
            key, equals, value = rest[0].partition("=")
            if equals and value:
                options.set_option(self.active, saved, key, value, **common)
            else:
                self.say("Usage: set NAME VALUE   or   set NAME=VALUE", "muted")
        else:
            options.set_option(
                self.active,
                saved,
                rest[0],
                " ".join(rest[1:]),
                tokens=rest[1:],
                **common,
            )
        return False

    def unset_value(self, rest: list[str]) -> bool:
        if self.active is None:
            self.say("No module is selected.", "muted")
        elif not rest:
            self.say("Usage: unset NAME   or   unset all", "muted")
        else:
            options.unset_option(self.settings.setdefault(self.active, {}), rest[0])
        return False

    # -- running ------------------------------------------------------------------------

    def run_selected(self, rest: list[str]) -> bool:
        if self.active is None:
            self.say(
                "Select a module first: use <module>, or type a module name with its arguments.",
                "muted",
            )
        else:
            self.invoke(self.active, rest)
        return False

    def invoke(self, name: str, argv: list[str]) -> None:
        merged = self.merger(
            name,
            argv,
            self.settings.get(name, {}),
            tool_file=self.tool_file,
            build_parser=self.build_parser,
        )
        if merged:
            ui.console.print(
                Text(
                    f"bughunt {name} {shlex.join(options.redacted_argv(name, merged))}"
                )
            )
        try:
            code = self.runner(
                name, merged, tool_file=self.tool_file, scan_main=self.scan_main
            )
        except KeyboardInterrupt:
            self.say("Interrupted.", "warn")
            code = 130
        if code:
            self.say(f"exit {code}", "muted")
        self.suggest_follow_ons(name)

    def suggest_follow_ons(self, name: str) -> None:
        follow = walkthrough.follow_ons(name)
        if not follow:
            return
        self.say("Next you might:", "muted")
        for module, why in follow:
            self.say(f"  {module:<10} {why}")

    def explain_unknown_command(self, head: str) -> None:
        from bughunt.console import cli

        guess = complete.suggest_console(head) or cli.suggest_command(head)
        if guess:
            self.say(f"Unknown command {head}. Did you mean {guess}?", "warn")
        elif self.active:
            self.say(
                f"Unknown command {head}. To run {self.active} with arguments, type: run <args>",
                "warn",
            )
        else:
            self.say(f"Unknown command {head}. Type help for the command list.", "warn")

    # -- dispatch -----------------------------------------------------------------------

    def handler_for(self, head: str):
        return {
            "exit": self.leave,
            "quit": self.leave,
            "help": self.show_help,
            "?": self.show_help,
            "banner": self.show_banner,
            "version": self.show_version,
            "doctor": self.run_doctor,
            "examples": self.show_examples,
            "search": self.search,
            "history": self.show_history,
            "show": self.show,
            "modules": self.modules,
            "commands": self.modules,
            "use": self.use,
            "back": self.back,
            "set": self.set_value,
            "unset": self.unset_value,
            "run": self.run_selected,
        }.get(head)

    def execute(self, tokens: list[str]) -> bool:
        """Carry out one parsed line; True means the console should close."""
        head, rest = tokens[0], tokens[1:]
        handler = self.handler_for(head)
        if handler is not None:
            return handler(rest)
        module = canonical_module(head)
        if module is None:
            self.explain_unknown_command(head)
            return False
        self.invoke(module, rest)
        return False


def _remember(session: _Session, line: str, recording: bool, tokens: list[str]) -> None:
    if complete.sensitive_line(line):
        return
    if len(tokens) > 1 and tokens[0].lower() == "set":
        key = tokens[1].partition("=")[0]
        if options.redacted_value(session.active or "", key, "") == termio.REDACTED:
            return
    session.transcript.append(line)
    if recording:
        import readline

        readline.add_history(line)


def _read_commands(
    session: _Session, reader: Callable[[str], str], recording: bool
) -> int:
    while True:
        complete_state = session.complete_state
        complete_state.active = session.active
        try:
            raw = reader(_prompt(session.active))
        except EOFError:
            ui.console.print()
            return 0
        except KeyboardInterrupt:
            ui.console.print()
            session.say("Type exit to leave the console.", "muted")
            continue
        if raw is None:
            return 0
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = options.split_words(line)
        except ValueError as exc:
            session.say(f"Could not parse that line: {exc}", "warn")
            continue
        leaving = session.execute(tokens)
        _remember(session, line, recording, tokens)
        if leaving:
            return 0


def run_console(
    *,
    tool_file: Path,
    scan_main: Callable,
    read_line: Callable[[str], str] | None = None,
    run_module: Callable | None = None,
    build_parser: Callable | None = None,
    merge_argv: Callable | None = None,
) -> int:
    from bughunt.modules import snare

    settings: dict[str, dict[str, str]] = {}
    session = _Session(
        tool_file=tool_file,
        scan_main=scan_main,
        build_parser=build_parser,
        runner=run_module if run_module is not None else loader.run_named,
        merger=merge_argv if merge_argv is not None else options.prepare_argv,
        settings=settings,
        complete_state=complete.CompleteState(tool_file, build_parser, settings),
    )
    reader = read_line
    recording = False
    if reader is None:
        reader = complete.install_reader(session.complete_state)
        recording = reader is not None
        if recording:
            session.transcript.extend(complete.load_history(complete.history_path()))
        else:
            reader = input
    snare.attach_console(_background_printer(recording))
    try:
        print_banner()
        return _read_commands(session, reader, recording)
    finally:
        if snare.job_tag():
            snare.stop_listener()
        else:
            snare.stop_listener(quiet=True)
        snare.attach_console(None)
        if recording:
            complete.save_history(complete.history_path(), session.transcript)
