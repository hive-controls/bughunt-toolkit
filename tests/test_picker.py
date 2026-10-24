"""Arrow-key picker, driven through Textual's pilot. No network, no real modules run."""

import asyncio
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")

from bughunt.console import options, picker
from bughunt.core import scanner as bughunt_scanner


@pytest.fixture(autouse=True)
def empty_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))


def _app(settings=None):
    return picker.BughuntPicker(
        tool_file=Path(bughunt_scanner.__file__),
        scan_main=bughunt_scanner.scan_main,
        build_parser=bughunt_scanner.build_parser,
        settings=settings if settings is not None else {},
    )


def _run(scenario):
    async def go():
        app = _app()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await scenario(app, pilot)

    asyncio.run(go())


def _highlighted_id(app):
    return app.screen.query_one(picker.OptionList).highlighted_option.id


@pytest.mark.parametrize("kind, repeatable", [("value", True), ("tail", False)])
@pytest.mark.parametrize(
    "raw, expected",
    [
        (
            r'C:\Temp\paths.txt "C:\Temp Folder\more.txt"',
            [r"C:\Temp\paths.txt", r"C:\Temp Folder\more.txt"],
        ),
        (r'"\\server\shared folder\"', ["\\\\server\\shared folder\\"]),
    ],
)
def test_normalized_value_preserves_windows_paths(
    monkeypatch, kind, repeatable, raw, expected
):
    monkeypatch.setattr(options, "sys", SimpleNamespace(platform="win32"))
    flag = picker.Flag(
        "PATHS", "paths", ("--paths",), kind, False, "", (), "", repeatable, False
    )
    assert shlex.split(picker.normalized_value(flag, raw)) == expected


def test_picker_masks_saved_and_default_credentials_and_command_previews():
    secret = "picker-private-cookie"
    spec = options.load_spec(
        "redirect", tool_file=Path(bughunt_scanner.__file__), build_parser=None
    )
    cookie = next(row for row in spec.options if row.name == "COOKIE")
    assert secret not in picker.flag_value_text(cookie, {"COOKIE": secret})
    assert secret not in picker.flag_value_text(cookie._replace(default=secret), {})
    screen = picker.ModuleScreen(
        "redirect", spec, {"COOKIE": secret, "TARGET": "http://127.0.0.1/"}
    )
    assert secret not in screen.command_line()


def test_picker_credential_editor_masks_the_value_without_changing_it():
    async def scenario(app, pilot):
        app.open_module("redirect")
        await pilot.pause()
        screen = app.screen
        screen.settings["COOKIE"] = "opaque-private-4821"
        screen.reload()
        index = next(
            index for index, row in enumerate(screen.rows) if row.name == "COOKIE"
        )
        screen.query_one(picker.DataTable).move_cursor(row=index)
        screen.action_edit()
        await pilot.pause()
        field = app.screen.query_one(picker.Input)
        assert field.password is True
        assert field.value == "opaque-private-4821"

    _run(scenario)


def test_home_lists_groups_and_starts_on_a_module():
    async def scenario(app, pilot):
        assert isinstance(app.screen, picker.HomeScreen)
        assert _highlighted_id(app) == "scope"

    _run(scenario)


def test_typing_filters_and_enter_opens_the_module():
    async def scenario(app, pilot):
        await pilot.press(*"redirect")
        await pilot.pause()
        assert _highlighted_id(app) == "redirect"
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, picker.ModuleScreen)
        assert app.screen.module == "redirect"

    _run(scenario)


def test_arrow_keys_move_and_right_opens_left_goes_back():
    async def scenario(app, pilot):
        await pilot.press("down")
        assert _highlighted_id(app) == "policy"
        await pilot.press("right")
        await pilot.pause()
        assert isinstance(app.screen, picker.ModuleScreen)
        await pilot.press("left")
        await pilot.pause()
        assert isinstance(app.screen, picker.HomeScreen)

    _run(scenario)


def test_guide_me_opens_walkthrough_and_a_step_opens_its_module():
    async def scenario(app, pilot):
        app.open_entry("::guide")
        await pilot.pause()
        assert isinstance(app.screen, picker.GuideScreen)
        assert _highlighted_id(app) == "scope"
        await pilot.press("right")
        await pilot.pause()
        assert isinstance(app.screen, picker.ModuleScreen)
        assert app.screen.module == "scope"

    _run(scenario)


def _open_redirect(app):
    app.open_module("redirect")


def _select_row(app, name):
    screen = app.screen
    row = next(index for index, flag in enumerate(screen.rows) if flag.name == name)
    screen.query_one(picker.DataTable).move_cursor(row=row)


def test_bool_toggles_and_value_is_typed_into_a_dialog():
    async def scenario(app, pilot):
        _open_redirect(app)
        await pilot.pause()
        _select_row(app, "INSECURE")
        await pilot.press("enter")
        assert app.settings["redirect"]["INSECURE"] == "true"
        await pilot.press("enter")
        assert "INSECURE" not in app.settings["redirect"]

        _select_row(app, "URL")
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, picker.TextScreen)
        await pilot.press(*"http://127.0.0.1/")
        await pilot.press("enter")
        await pilot.pause()
        assert app.settings["redirect"]["URL"] == "http://127.0.0.1/"
        assert "bughunt redirect http://127.0.0.1/" in app.screen.command_line()

    _run(scenario)


def test_escape_in_a_dialog_keeps_the_old_value():
    async def scenario(app, pilot):
        _open_redirect(app)
        await pilot.pause()
        app.settings["redirect"]["LIMIT"] = "3"
        app.screen.reload()
        _select_row(app, "LIMIT")
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("backspace", "9", "escape")
        await pilot.pause()
        assert app.settings["redirect"]["LIMIT"] == "3"

    _run(scenario)


def test_run_confirms_then_hands_over_the_rendered_argv(monkeypatch):
    calls = []

    async def scenario(app, pilot):
        monkeypatch.setattr(
            app, "run_module", lambda name, argv: calls.append((name, argv))
        )
        _open_redirect(app)
        await pilot.pause()
        app.settings["redirect"].update({"URL": "http://127.0.0.1/", "LIMIT": "3"})
        app.screen.reload()
        await pilot.press("r")
        await pilot.pause()
        assert isinstance(app.screen, picker.RunScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert calls == []
        await pilot.press("r")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert calls == [("redirect", ["--limit", "3", "http://127.0.0.1/"])]

    _run(scenario)


def test_disabled_addon_does_not_open(monkeypatch):
    monkeypatch.setattr(picker, "DISABLED_REFERENCES", frozenset({"tcurl"}))

    async def scenario(app, pilot):
        app.open_entry("tcurl")
        await pilot.pause()
        assert isinstance(app.screen, picker.HomeScreen)

    _run(scenario)


def test_reenabled_addon_opens_normally():
    async def scenario(app, pilot):
        app.open_entry("skiff")
        await pilot.pause()
        assert isinstance(app.screen, picker.ModuleScreen)
        assert app.screen.module == "skiff"

    _run(scenario)


def test_command_line_entry_exits_to_the_typed_console():
    async def scenario(app, pilot):
        app.open_entry("::console")
        await pilot.pause()
        assert app.return_value == "console"

    _run(scenario)
