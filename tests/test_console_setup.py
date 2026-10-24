"""`bughunt setup` orchestration, hermetic: subprocess, venv creation and the workspace are all mocked."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from bughunt.console import setup


@pytest.fixture
def harness(monkeypatch, tmp_path):
    """A fake checkout with the lock file; records every command and venv creation."""
    root = tmp_path / "checkout"
    root.mkdir()
    (root / setup.LOCK_FILE).write_text("", encoding="utf-8")
    state = {"commands": [], "venvs": [], "failing": None, "workspace": 0}

    def fake_run(command, cwd):
        state["commands"].append(list(command))
        if state["failing"] is not None and state["failing"](command):
            return 3
        return 0

    def fake_create(venv_dir):
        state["venvs"].append(venv_dir)
        interpreter = setup.venv_python(venv_dir)
        interpreter.parent.mkdir(parents=True)
        interpreter.write_text("", encoding="utf-8")

    monkeypatch.setattr(setup, "checkout_root", lambda: root)
    monkeypatch.setattr(setup, "_run_command", fake_run)
    monkeypatch.setattr(setup, "_create_venv", fake_create)
    monkeypatch.setattr(setup, "_workspace_stage", lambda: state.__setitem__("workspace", state["workspace"] + 1))
    monkeypatch.setattr(setup, "_next_step_line", lambda: None)
    state["root"] = root
    return state


def _joined(state):
    return [" ".join(command) for command in state["commands"]]


def test_checkout_full_flow_creates_venv_installs_and_self_checks(harness, capsys):
    assert setup.run([]) == 0
    interpreter = str(setup.venv_python(harness["root"] / ".venv"))
    lines = _joined(harness)
    assert harness["venvs"] == [harness["root"] / ".venv"]
    assert lines[0] == f"{interpreter} -m pip install -r {harness['root'] / setup.LOCK_FILE}"
    assert lines[1] == f"{interpreter} -m pip install -e {harness['root']}"
    assert lines[2:] == [f"{interpreter} -m bughunt version", f"{interpreter} -m bughunt doctor"]
    assert harness["workspace"] == 1
    assert "[browser] skipped" in capsys.readouterr().out


def test_interpreter_path_follows_platform(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    assert setup.venv_python(tmp_path) == tmp_path / "Scripts" / "python.exe"
    monkeypatch.setattr(sys, "platform", "linux")
    assert setup.venv_python(tmp_path) == tmp_path / "bin" / "python"


def test_installed_wheel_skips_install_stage_and_venv(harness, capsys):
    (harness["root"] / setup.LOCK_FILE).unlink()
    assert setup.run([]) == 0
    assert harness["venvs"] == []
    assert all("pip" not in line for line in _joined(harness))
    assert _joined(harness)[0] == f"{sys.executable} -m bughunt version"
    assert "already installed" in capsys.readouterr().out


@pytest.mark.parametrize("minor", [9, 10, 11])
def test_python_below_minimum_is_refused_before_any_command(harness, monkeypatch, capsys, minor):
    monkeypatch.setattr(sys, "version_info", (3, minor, 18, "final", 0))
    assert setup.run([]) == 1
    assert harness["commands"] == [] and harness["venvs"] == []
    assert "3.12" in capsys.readouterr().out


def test_python_3_12_exactly_passes(harness, monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 12, 0, "final", 0))
    assert setup.run([]) == 0
    assert harness["commands"]


def test_minimum_python_without_installed_doctor_dependencies(monkeypatch):
    monkeypatch.setitem(sys.modules, "bughunt.console.doctor", None)
    assert setup._minimum_python() == (3, 12)


def test_existing_venv_is_reused_not_recreated(harness, capsys):
    interpreter = setup.venv_python(harness["root"] / ".venv")
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("", encoding="utf-8")
    assert setup.run([]) == 0
    assert harness["venvs"] == []
    assert "reusing existing venv" in capsys.readouterr().out


def test_custom_venv_dir_is_honoured(harness, tmp_path):
    custom = tmp_path / "elsewhere"
    assert setup.run(["--venv", str(custom)]) == 0
    assert harness["venvs"] == [custom]


def test_no_venv_installs_into_current_interpreter(harness):
    assert setup.run(["--no-venv"]) == 0
    assert harness["venvs"] == []
    assert _joined(harness)[0].startswith(f"{sys.executable} -m pip install -r")


def test_browser_is_opt_in(harness):
    assert setup.run([]) == 0
    assert not any("playwright" in line for line in _joined(harness))
    harness["commands"].clear()
    assert setup.run(["--browser"]) == 0
    assert any(line.endswith("-m playwright install chromium") for line in _joined(harness))


def test_no_workspace_skips_workspace_stage(harness, capsys):
    assert setup.run(["--no-workspace"]) == 0
    assert harness["workspace"] == 0
    assert "--no-workspace" in capsys.readouterr().out


def test_failed_stage_returns_nonzero_naming_the_command_and_stops(harness, capsys):
    harness["failing"] = lambda command: "-e" in command
    assert setup.run([]) == 3
    output = capsys.readouterr().out
    assert "FAILED (exit 3)" in output and "pip install -e" in output
    assert not any("bughunt version" in line for line in _joined(harness))
    assert harness["workspace"] == 0


def test_failed_self_check_is_nonzero(harness, capsys):
    harness["failing"] = lambda command: command[-1] == "doctor"
    assert setup.run([]) == 3
    assert "-m bughunt doctor" in capsys.readouterr().out


def test_missing_python3_venv_prints_distro_hint(harness, monkeypatch, capsys):
    def broken(_venv_dir):
        raise subprocess.CalledProcessError(1, ["python", "-m", "ensurepip"])

    monkeypatch.setattr(setup, "_create_venv", broken)
    assert setup.run([]) == 1
    assert "python3-venv" in capsys.readouterr().out
    assert harness["commands"] == []


def test_is_source_checkout_detects_lock_file(tmp_path):
    assert not setup.is_source_checkout(tmp_path)
    (tmp_path / setup.LOCK_FILE).write_text("", encoding="utf-8")
    assert setup.is_source_checkout(tmp_path)


def test_cli_registration_routes_setup_and_help(capsys):
    from bughunt.console import cli

    assert cli.route_argv(["setup", "--browser"]).command == "setup"
    assert Path(setup.__file__).name == "setup.py"
    assert "setup" in cli._COMMAND_WORDS
