"""Shared terminal plumbing: tty guard, colour rule, stderr note, banner display."""

import io

import pytest

from bughunt.core import termio


class TtyStream(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self.tty = tty
        self.flushes = 0

    def isatty(self) -> bool:
        return self.tty

    def flush(self) -> None:
        self.flushes += 1
        super().flush()


class RaisingStream:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def isatty(self) -> bool:
        raise self.error


class TruthyStream:
    def isatty(self) -> int:
        return 1


def set_env(monkeypatch, no_color, term) -> None:
    for name, value in (("NO_COLOR", no_color), ("TERM", term)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def test_stream_is_tty_reports_the_stream_answer():
    assert termio.stream_is_tty(TtyStream(True)) is True
    assert termio.stream_is_tty(TtyStream(False)) is False


def test_stream_is_tty_coerces_to_bool():
    assert termio.stream_is_tty(TruthyStream()) is True


def test_stream_is_tty_is_false_without_isatty():
    assert termio.stream_is_tty(object()) is False


@pytest.mark.parametrize("error", [AttributeError("gone"), ValueError("closed")])
def test_stream_is_tty_is_false_when_isatty_raises(error):
    assert termio.stream_is_tty(RaisingStream(error)) is False


def test_stream_is_tty_is_false_on_a_closed_stream():
    stream = io.StringIO()
    stream.close()
    assert termio.stream_is_tty(stream) is False


@pytest.mark.parametrize(
    ("no_color", "term", "tty", "expected"),
    [
        (None, "xterm", True, True),
        ("", "xterm", True, True),
        (None, "xterm", False, False),
        (None, "xterm-256color", True, True),
        ("1", "xterm", True, False),
        (" ", "xterm", True, False),
        ("0", "xterm", True, False),
        (None, None, True, False),
        (None, "", True, False),
        (None, "dumb", True, False),
        ("", "dumb", True, False),
        ("1", "dumb", False, False),
        ("1", None, True, False),
    ],
)
def test_color_enabled_matrix(monkeypatch, no_color, term, tty, expected):
    set_env(monkeypatch, no_color, term)
    assert termio.color_enabled(TtyStream(tty)) is expected


def test_color_enabled_is_false_when_the_stream_has_no_isatty(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    assert termio.color_enabled(object()) is False
    assert termio.color_enabled(RaisingStream(ValueError("closed"))) is False


def test_color_enabled_reads_the_environment_at_call_time(monkeypatch):
    stream = TtyStream(True)
    set_env(monkeypatch, None, "xterm")
    assert termio.color_enabled(stream) is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert termio.color_enabled(stream) is False
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert termio.color_enabled(stream) is False


def test_color_enabled_judges_each_stream_on_its_own(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    assert termio.color_enabled(TtyStream(True)) is True
    assert termio.color_enabled(TtyStream(False)) is False


def test_say_writes_one_line_to_stderr_only(capsys):
    termio.say("Give a token.")
    captured = capsys.readouterr()
    assert captured.err == "Give a token.\n"
    assert captured.out == ""


def test_say_flushes_stderr(monkeypatch):
    stderr = TtyStream(False)
    monkeypatch.setattr("sys.stderr", stderr)
    termio.say("hello")
    assert stderr.getvalue() == "hello\n"
    assert stderr.flushes >= 1


def test_say_follows_a_replaced_stderr(monkeypatch, capsys):
    first, second = TtyStream(False), TtyStream(False)
    monkeypatch.setattr("sys.stderr", first)
    termio.say("one")
    monkeypatch.setattr("sys.stderr", second)
    termio.say("two")
    assert (first.getvalue(), second.getvalue()) == ("one\n", "two\n")
    assert capsys.readouterr().err == ""


class Renderer:
    def __init__(self) -> None:
        self.calls: list[bool] = []

    def __call__(self, color: bool) -> str:
        self.calls.append(color)
        return "COLOR-BANNER" if color else "PLAIN-BANNER"


def test_show_banner_prints_nothing_when_stderr_is_not_a_tty(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    stderr = TtyStream(False)
    monkeypatch.setattr("sys.stderr", stderr)
    render = Renderer()
    termio.show_banner(render)
    assert render.calls == []
    assert stderr.getvalue() == ""


def test_show_banner_prints_nothing_when_stderr_has_no_isatty(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    render = Renderer()
    monkeypatch.setattr("sys.stderr", RaisingStream(ValueError("closed")))
    termio.show_banner(render)
    assert render.calls == []


def test_show_banner_on_a_colour_terminal_adds_exactly_one_blank_line(monkeypatch, capsys):
    set_env(monkeypatch, None, "xterm")
    stderr = TtyStream(True)
    monkeypatch.setattr("sys.stderr", stderr)
    render = Renderer()
    termio.show_banner(render)
    assert render.calls == [True]
    assert stderr.getvalue() == "COLOR-BANNER\n\n"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(("no_color", "term"), [("1", "xterm"), (None, "dumb"), (None, ""), (None, None)])
def test_show_banner_on_a_tty_without_colour_still_prints_plain(monkeypatch, no_color, term):
    set_env(monkeypatch, no_color, term)
    stderr = TtyStream(True)
    monkeypatch.setattr("sys.stderr", stderr)
    render = Renderer()
    termio.show_banner(render)
    assert render.calls == [False]
    assert stderr.getvalue() == "PLAIN-BANNER\n\n"


def test_show_banner_decides_on_stderr_not_stdout(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    stdout, stderr = TtyStream(True), TtyStream(False)
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)
    render = Renderer()
    termio.show_banner(render)
    assert render.calls == []
    assert stdout.getvalue() == stderr.getvalue() == ""


def test_show_banner_writes_to_stderr_not_stdout(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    stdout, stderr = TtyStream(True), TtyStream(True)
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)
    termio.show_banner(Renderer())
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "COLOR-BANNER\n\n"


def test_utc_stamp_formats_a_utc_moment_with_a_z_suffix():
    from datetime import datetime, timezone

    assert datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc).strftime(termio.UTC_STAMP) == "2026-01-02 03:04:05Z"


@pytest.mark.parametrize(
    ("plain", "tty", "expected"),
    [(False, True, True), (False, False, False), (True, True, False), (True, False, False)],
)
def test_stdout_color_needs_a_terminal_and_no_plain_request(monkeypatch, plain, tty, expected):
    set_env(monkeypatch, None, "xterm")
    monkeypatch.setattr("sys.stdout", TtyStream(tty))
    assert termio.stdout_color(plain) is expected


def test_stdout_color_honours_no_color(monkeypatch):
    set_env(monkeypatch, "1", "xterm")
    monkeypatch.setattr("sys.stdout", TtyStream(True))
    assert termio.stdout_color(False) is False


def test_stdout_color_does_not_look_at_stderr(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    monkeypatch.setattr("sys.stdout", TtyStream(False))
    monkeypatch.setattr("sys.stderr", TtyStream(True))
    assert termio.stdout_color(False) is False


def test_open_output_with_plain_shows_nothing_and_answers_no_colour(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    stdout, stderr = TtyStream(True), TtyStream(True)
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)
    render = Renderer()
    assert termio.open_output(True, render) is False
    assert render.calls == []
    assert stderr.getvalue() == ""


def test_open_output_shows_the_banner_on_stderr_and_answers_for_stdout(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    stdout, stderr = TtyStream(True), TtyStream(True)
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)
    render = Renderer()
    assert termio.open_output(False, render) is True
    assert render.calls == [True]
    assert stderr.getvalue() == "COLOR-BANNER\n\n"
    assert stdout.getvalue() == ""


def test_open_output_answers_no_colour_when_stdout_is_piped_even_with_a_banner(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    monkeypatch.setattr("sys.stdout", TtyStream(False))
    stderr = TtyStream(True)
    monkeypatch.setattr("sys.stderr", stderr)
    assert termio.open_output(False, Renderer()) is False
    assert stderr.getvalue() == "COLOR-BANNER\n\n"


def test_open_output_without_a_stderr_terminal_prints_no_banner_but_still_judges_stdout(monkeypatch):
    set_env(monkeypatch, None, "xterm")
    monkeypatch.setattr("sys.stdout", TtyStream(True))
    stderr = TtyStream(False)
    monkeypatch.setattr("sys.stderr", stderr)
    render = Renderer()
    assert termio.open_output(False, render) is True
    assert render.calls == []
    assert stderr.getvalue() == ""
