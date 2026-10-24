"""Arrow-key picker for the Bughunt console.

Bare `bughunt` (and `bughunt console`) in a terminal opens this. Up and down
move, Enter or Right opens, Esc or Left goes back, and typing filters. A module
opens as a form built from its argparse options, the same Spec the text console
uses. Run shows the command line first, then hands the terminal to the module
until it finishes. `bughunt console --text` keeps the typed console.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from bughunt import VERSION
from bughunt.console import guide, readiness
from bughunt.console.catalog import (
    DISABLED_REFERENCES,
    MODULE_GROUPS,
    module_when,
    phase_purpose,
)
from bughunt.console.loader import ScanMain, run_named
from bughunt.console.options import Option as Flag
from bughunt.console.options import (
    Spec,
    SpecError,
    _TRUE,
    _active_command,
    _visible,
    load_spec,
    redacted_argv,
    redacted_value,
    render_argv,
    split_words,
)

TOOLS = (
    (
        "::guide",
        "Guide me",
        "A step-by-step walkthrough of the hunt from where you are.",
    ),
    (
        "::console",
        "Command line",
        "The typed console: use, set, run. exit comes back here.",
    ),
    ("::doctor", "Doctor", "Check Python and packages."),
    ("::exit", "Exit", "Leave Bughunt."),
)


def module_summary(name: str) -> str:
    from bughunt.console.console import _module_facts

    return _module_facts(name)[0]


def browser_rows(needle: str) -> list[tuple[str | None, str, str]]:
    """(id, label, summary) rows for the home list. id None is a group heading."""
    needle = needle.strip().lower()
    rows: list[tuple[str | None, str, str]] = []
    for title, members in MODULE_GROUPS:
        matched = [
            name
            for name in members
            if not needle or needle in name or needle in module_summary(name).lower()
        ]
        if matched:
            rows.append((None, title, phase_purpose(title)))
            rows.extend((name, name, module_summary(name)) for name in matched)
    tools = [tool for tool in TOOLS if not needle or needle in tool[1].lower()]
    if tools:
        rows.append((None, "Bughunt", ""))
        rows.extend(tools)
    return rows


def flag_value_text(flag: Flag, settings: dict[str, str], module_name: str = "") -> str:
    value = settings.get(flag.name)
    if value:
        return redacted_value(module_name, flag.name, value, option_kind=flag.kind)
    return (
        f"[dim]{escape(redacted_value(module_name, flag.name, flag.default, option_kind=flag.kind))}[/dim]"
        if flag.default
        else "[dim]·[/dim]"
    )


def normalized_value(flag: Flag, raw: str) -> str:
    """Store values the way `set` does. Raises ValueError on unbalanced quotes."""
    if flag.repeatable or flag.kind == "tail":
        return shlex.join(split_words(raw))
    return raw


class HomeScreen(Screen):
    BINDINGS = [
        Binding("escape", "clear_filter", "Clear filter"),
        Binding("right", "open", "Open", show=False),
        Binding("ctrl+q", "app.quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="status")
        yield Input(placeholder="type to filter modules", id="filter")
        yield OptionList(id="modules")
        yield Static(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        self.readiness = readiness.gather()
        self.query_one("#status", Static).update(self._status_text())
        self.refill("")
        self.query_one(OptionList).focus()

    def _status_text(self) -> str:
        _module, message = self.readiness.next_step()
        mark = "[green]✓[/green]" if not _module else "[yellow]⚠[/yellow]"
        return f"{mark} {escape(message)}"

    def refill(self, needle: str) -> None:
        listing = self.query_one(OptionList)
        listing.clear_options()
        for row_id, label, summary in browser_rows(needle):
            if row_id is None:
                block = self.readiness.phase_block(label)
                gate = f"  [yellow]⚠ {escape(block)}[/yellow]" if block else ""
                purpose = f"  [dim]{escape(summary)}[/dim]" if summary else ""
                listing.add_option(
                    Option(f"[b]{escape(label)}[/b]{purpose}{gate}", disabled=True)
                )
                continue
            note = (
                "  [dim](disabled in this fork)[/dim]"
                if row_id in DISABLED_REFERENCES
                else ""
            )
            listing.add_option(
                Option(
                    f"  {escape(label):<10} [dim]{escape(summary)}[/dim]{note}",
                    id=row_id,
                )
            )
        first = next(
            (
                index
                for index in range(listing.option_count)
                if not listing.get_option_at_index(index).disabled
            ),
            None,
        )
        listing.highlighted = first

    def on_input_changed(self, event: Input.Changed) -> None:
        self.refill(event.value)

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self.action_open()

    def on_key(self, event) -> None:
        box = self.query_one("#filter", Input)
        if box.has_focus:
            if event.key in ("up", "down"):
                self.query_one(OptionList).focus()
            return
        if (
            event.character
            and event.character.isprintable()
            and event.key not in ("space",)
        ):
            box.focus()
            box.value += event.character
            box.cursor_position = len(box.value)
            event.stop()

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        option_id = event.option.id or ""
        tool = next((tool for tool in TOOLS if tool[0] == option_id), None)
        if tool:
            text = tool[2]
        else:
            text = module_when(option_id) or module_summary(option_id)
        self.query_one("#detail", Static).update(escape(text))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.app.open_entry(event.option.id or "")

    def action_open(self) -> None:
        option = self.query_one(OptionList).highlighted_option
        if option is not None and option.id:
            self.app.open_entry(option.id)

    def action_clear_filter(self) -> None:
        box = self.query_one("#filter", Input)
        box.value = ""
        self.query_one(OptionList).focus()


class GuideScreen(Screen):
    """A step-by-step walkthrough. Each step opens that module when chosen."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("left", "app.pop_screen", "Back", show=False),
        Binding("right", "open", "Open", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "[b]Guided walkthrough[/b]  the hunt from where you are", id="guidetitle"
        )
        yield OptionList(id="steps")
        yield Static(id="guidedetail")
        yield Footer()

    def on_mount(self) -> None:
        listing = self.query_one(OptionList)
        self._why: dict[str, str] = {}
        for index, step in enumerate(guide.plan(), 1):
            mark = (
                "[green]ready[/green]"
                if step.ready
                else f"[yellow]⚠ {escape(step.blocked_reason)}[/yellow]"
            )
            listing.add_option(
                Option(f"{index}. [b]{escape(step.module)}[/b]  {mark}", id=step.module)
            )
            follow = "   ".join(
                f"→ {nxt}" for nxt, _why in guide.follow_ons(step.module)
            )
            self._why[step.module] = step.why + (
                f"\n[dim]then: {escape(follow)}[/dim]" if follow else ""
            )
        if listing.option_count:
            listing.highlighted = 0
        listing.focus()

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        self.query_one("#guidedetail", Static).update(
            self._why.get(event.option.id or "", "")
        )

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.app.open_entry(event.option.id)

    def action_open(self) -> None:
        option = self.query_one(OptionList).highlighted_option
        if option is not None and option.id:
            self.app.open_entry(option.id)


class ModuleScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("left", "app.pop_screen", "Back", show=False),
        Binding("right", "edit", "Edit", show=False),
        Binding("r", "run", "Run"),
        Binding("delete", "clear", "Clear value"),
        Binding("backspace", "clear", "Clear value", show=False),
    ]

    def __init__(self, name: str, spec: Spec, settings: dict[str, str]) -> None:
        super().__init__()
        self.module = name
        self.spec = spec
        self.settings = settings
        self.rows: list[Flag] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            f"[b]bughunt {escape(self.module)}[/b]  {escape(module_summary(self.module))}",
            id="title",
        )
        yield DataTable(cursor_type="row", zebra_stripes=True, id="flags")
        yield Static(id="help")
        yield Static(id="preview")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Option", "Value", "Required", "Flag")
        self.reload()
        table.focus()

    def reload(self) -> None:
        table = self.query_one(DataTable)
        keep = table.cursor_row
        table.clear()
        self.rows = _visible(self.spec, _active_command(self.spec, self.settings))
        for flag in self.rows:
            required = "[b]yes[/b]" if flag.required else ""
            table.add_row(
                flag.name,
                flag_value_text(flag, self.settings, self.module),
                required,
                " ".join(flag.flags),
            )
        if self.rows:
            table.move_cursor(row=min(keep, len(self.rows) - 1))
        self.query_one("#preview", Static).update(
            f"[dim]$[/dim] {escape(self.command_line())}"
        )

    def command_line(self) -> str:
        argv = render_argv(self.spec, self.settings, [])
        return shlex.join(["bughunt", self.module, *redacted_argv(self.module, argv)])

    def current(self) -> Flag | None:
        row = self.query_one(DataTable).cursor_row
        return self.rows[row] if 0 <= row < len(self.rows) else None

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        flag = self.current()
        if flag is None:
            return
        choices = (
            f"  [dim]choices: {escape(', '.join(flag.choices))}[/dim]"
            if flag.choices
            else ""
        )
        self.query_one("#help", Static).update(
            escape(flag.help or "No description.") + choices
        )

    def on_data_table_row_selected(self, _event: DataTable.RowSelected) -> None:
        self.action_edit()

    def action_edit(self) -> None:
        flag = self.current()
        if flag is None:
            return
        if flag.kind == "bool":
            enabled = self.settings.get(flag.name, "").lower() in _TRUE
            self.store(flag, "" if enabled else "true")
        elif flag.choices:
            self.app.push_screen(
                ChoiceScreen(flag, self.settings.get(flag.name, "")),
                lambda value: self.store(flag, value),
            )
        else:
            self.app.push_screen(
                TextScreen(
                    flag, self.settings.get(flag.name, ""), module_name=self.module
                ),
                lambda value: self.store(flag, value),
            )

    def store(self, flag: Flag, value: str | None) -> None:
        if value is None:
            return
        if not value:
            self.settings.pop(flag.name, None)
        else:
            try:
                self.settings[flag.name] = normalized_value(flag, value)
            except ValueError as exc:
                self.notify(f"{flag.name}: {exc}", severity="error")
                return
        self.reload()

    def action_clear(self) -> None:
        flag = self.current()
        if flag is not None:
            self.store(flag, "")

    def action_run(self) -> None:
        missing = [
            flag.name
            for flag in self.rows
            if flag.required and not self.settings.get(flag.name)
        ]
        self.app.push_screen(
            RunScreen(self.command_line(), missing), self.after_confirm
        )

    def after_confirm(self, go: bool | None) -> None:
        if go:
            self.app.run_module(self.module, render_argv(self.spec, self.settings, []))


class ChoiceScreen(ModalScreen[str | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("left", "cancel", "Cancel", show=False),
    ]

    def __init__(self, flag: Flag, current: str) -> None:
        super().__init__()
        self.flag = flag
        self.current = current

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(f"[b]{escape(self.flag.name)}[/b]  {escape(self.flag.help)}")
            yield OptionList(
                *[Option(escape(choice), id=choice) for choice in self.flag.choices],
                Option("[dim](clear)[/dim]", id=""),
            )

    def on_mount(self) -> None:
        listing = self.query_one(OptionList)
        listing.highlighted = (
            self.flag.choices.index(self.current)
            if self.current in self.flag.choices
            else 0
        )
        listing.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id or "")

    def action_cancel(self) -> None:
        self.dismiss(None)


class TextScreen(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, flag: Flag, current: str, *, module_name: str = "") -> None:
        super().__init__()
        self.flag = flag
        self.current = current
        self.module_name = module_name

    def compose(self) -> ComposeResult:
        hint = (
            "Several values: separate with spaces, quote ones that contain spaces."
            if self.flag.repeatable or self.flag.kind == "tail"
            else ""
        )
        with Vertical(classes="dialog"):
            yield Label(f"[b]{escape(self.flag.name)}[/b]  {escape(self.flag.help)}")
            placeholder = (
                redacted_value(self.module_name, self.flag.name, self.flag.default)
                if self.flag.default
                else "empty clears the value"
            )
            private = (
                redacted_value(self.module_name, self.flag.name, self.current)
                != self.current
            )
            yield Input(value=self.current, placeholder=placeholder, password=private)
            yield Label(f"[dim]Enter saves. Esc cancels. {escape(hint)}[/dim]")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class RunScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel"), Binding("enter", "go", "Run")]

    def __init__(self, command: str, missing: list[str]) -> None:
        super().__init__()
        self.command = command
        self.missing = missing

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("[b]Run this?[/b]")
            yield Label(f"$ {escape(self.command)}")
            if self.missing:
                yield Label(
                    f"[yellow]Required and empty: {escape(', '.join(self.missing))}[/yellow]"
                )
            yield Label("[dim]Enter runs. Esc goes back to the options.[/dim]")

    def action_go(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class BughuntPicker(App[str | None]):
    TITLE = f"Bughunt {VERSION}"
    SUB_TITLE = "authorized HTTP toolkit"
    CSS = """
    #status { height: auto; margin: 1 2 0 2; }
    #filter { margin: 0 1; }
    #modules { height: 1fr; margin: 0 1; }
    #detail, #help, #preview { height: auto; margin: 0 2; }
    #guidetitle { margin: 1 2 0 2; }
    #steps { height: 1fr; margin: 0 1; }
    #guidedetail { height: auto; margin: 0 2; }
    #title { margin: 1 2 0 2; }
    #flags { height: 1fr; margin: 1 1 0 1; }
    ModalScreen { align: center middle; }
    .dialog { width: 80%; height: auto; max-height: 80%; border: round $accent; background: $surface; padding: 1 2; }
    .dialog OptionList { height: auto; max-height: 20; }
    """

    def __init__(
        self,
        *,
        tool_file: Path,
        scan_main: ScanMain,
        build_parser,
        settings: dict[str, dict[str, str]],
    ) -> None:
        super().__init__()
        self.tool_file = tool_file
        self.scan_main = scan_main
        self.build_parser = build_parser
        self.settings = settings

    def on_mount(self) -> None:
        self.push_screen(HomeScreen())

    def open_entry(self, entry: str) -> None:
        if entry == "::exit":
            self.exit(None)
        elif entry == "::guide":
            self.push_screen(GuideScreen())
        elif entry == "::console":
            self.exit("console")
        elif entry == "::doctor":
            self.hand_over(self._doctor)
        elif entry in DISABLED_REFERENCES:
            self.notify(f"{entry} is disabled in this fork.", severity="warning")
        else:
            self.open_module(entry)

    def open_module(self, name: str) -> None:
        try:
            spec = load_spec(
                name, tool_file=self.tool_file, build_parser=self.build_parser
            )
        except SpecError as exc:
            self.notify(exc.message, severity="error")
            return
        self.push_screen(ModuleScreen(name, spec, self.settings.setdefault(name, {})))

    def run_module(self, name: str, argv: list[str]) -> None:
        def go() -> int:
            print(shlex.join(["bughunt", name, *redacted_argv(name, argv)]), flush=True)
            code = run_named(
                name, argv, tool_file=self.tool_file, scan_main=self.scan_main
            )
            nexts = guide.follow_ons(name)
            if nexts:
                print("\nNext you might:")
                for nxt, why in nexts:
                    print(f"  {nxt}  — {why}")
            return code

        self.hand_over(go)

    def _doctor(self) -> int:
        from bughunt.console.doctor import run as run_doctor

        return run_doctor(self.tool_file)

    def hand_over(self, work) -> None:
        """Give the terminal to `work`, then wait for Enter and come back."""
        with self.suspend():
            try:
                code = work()
            except KeyboardInterrupt:
                print("\nInterrupted.")
                code = 130
            if code:
                print(f"exit {code}")
            try:
                input("\nPress Enter to return to Bughunt. ")
            except (EOFError, KeyboardInterrupt):
                pass
        self.refresh()


def run_picker(*, tool_file: Path, scan_main: ScanMain, build_parser) -> int:
    """Picker until Exit. Command line drops to the typed console and comes back."""
    from bughunt.console.console import run_console
    from bughunt.modules.snare import attach_console, job_tag, stop_listener

    settings: dict[str, dict[str, str]] = {}
    try:
        while True:
            app = BughuntPicker(
                tool_file=tool_file,
                scan_main=scan_main,
                build_parser=build_parser,
                settings=settings,
            )
            attach_console(
                lambda line: app.call_from_thread(app.notify, line, title="snare")
            )
            choice = app.run()
            attach_console(None)
            if choice != "console":
                return 0
            run_console(
                tool_file=tool_file, scan_main=scan_main, build_parser=build_parser
            )
    finally:
        attach_console(None)
        stop_listener(quiet=not job_tag())
