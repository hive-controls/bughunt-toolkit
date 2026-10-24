"""Characterization oracle for `bughunt.console.loader` (M2 clean-room rebuild, spec section 4).

Fake reference tools are dropped into a scratch `addons/` tree anchored by a scratch `tool_file`
(the post-M0 `parents[2]` rule), so `run_named` is exercised end to end (locate, import, call
`main`, map the result) without touching the real addons. Nothing here uses the network.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

from bughunt.console import catalog, loader
from bughunt.core import egress

from console_support import (  # noqa: F401  (env is a pytest fixture)
    ScanRecorder,
    env,
    forbidden_scan,
    make_project,
)

PROBE_MAIN = """
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
IMPORT_TIME_PATH_HAS_PARENT = HERE in sys.path
def main(argv):
    with open(os.path.join(HERE, "probe.json"), "w", encoding="utf-8") as handle:
        json.dump({
            "argv": list(argv),
            "same_object_as_caller": False,
            "sys_argv": list(sys.argv),
            "parent_on_path": HERE in sys.path,
            "import_time_parent_on_path": IMPORT_TIME_PATH_HAS_PARENT,
        }, handle)
    return 0
"""


def run_tool(env, source: str, argv=None, *, name: str = "pulse", sub: str = "p") -> int:
    """Run a fake reference tool whose script is `source`; returns run_named's code."""
    env.activate()
    tool_file = make_project(env.root / sub, {name: source})
    return loader.run_named(name, list(argv or []), tool_file=tool_file, scan_main=forbidden_scan)


# --------------------------------------------------------------------------------------
# exit_code (4.1) and looks_like_python (4.4)
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "code,expected",
    [(None, 0), (0, 0), (1, 1), (2, 2), (130, 130), (-1, -1), ("bye", 1), ("", 1), (2.5, 1), (True, True), (False, 0), ((1, 2), 1)],
)
def test_exit_code_mapping(code, expected):
    result = loader.exit_code(SystemExit(code))
    assert result == expected
    if code is True:
        assert result is True  # spec 11.9: bool is an int, returned unchanged


def test_exit_code_of_a_bare_systemexit_is_zero():
    assert loader.exit_code(SystemExit()) == 0


def test_looks_like_python_by_suffix(tmp_path):
    for name in ("a.py", "b.PY", "c.Py"):
        script = tmp_path / name
        script.write_text("# not python at all\n", encoding="utf-8")
        assert loader.looks_like_python(script) is True


@pytest.mark.parametrize(
    "first_line,expected",
    [
        ("#!/usr/bin/env python3", True),
        ("#!/usr/bin/python", True),
        ("#!/usr/bin/env PYTHON", True),
        ("#!/bin/bash", False),
        ("echo hello", False),
        ("", False),
    ],
)
def test_looks_like_python_by_first_line_for_files_without_a_suffix(tmp_path, first_line, expected):
    script = tmp_path / "prog"
    script.write_text(first_line + "\nsecond python line\n", encoding="utf-8")
    assert loader.looks_like_python(script) is expected


def test_looks_like_python_reads_at_most_two_hundred_characters_of_the_first_line(tmp_path):
    script = tmp_path / "prog"
    script.write_text("#!/bin/sh " + "x" * 300 + " python\n", encoding="utf-8")
    assert loader.looks_like_python(script) is False
    script.write_text("#!/bin/sh " + "x" * 150 + " python\n", encoding="utf-8")
    assert loader.looks_like_python(script) is True


def test_looks_like_python_for_an_unreadable_file_is_false(tmp_path):
    assert loader.looks_like_python(tmp_path / "missing") is False


def test_looks_like_python_replaces_undecodable_bytes(tmp_path):
    script = tmp_path / "prog"
    script.write_bytes(b"#!\xff\xfe python\n")
    assert loader.looks_like_python(script) is True


# --------------------------------------------------------------------------------------
# 4.7 import_script
# --------------------------------------------------------------------------------------

def _write(path: Path, source: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def test_import_script_registers_the_module_under_a_path_hashed_key(tmp_path):
    script = _write(tmp_path / "my-tool.py", "VALUE = 41\n")
    module = loader.import_script(script)
    digest = hashlib.sha1(str(script.resolve()).encode()).hexdigest()[:12]
    key = f"bughunt_tools.my_tool_{digest}"
    assert module.__name__ == key
    assert sys.modules[key] is module
    assert module.VALUE == 41
    assert Path(module.__file__) == script.resolve()


def test_import_script_caches_per_resolved_path(tmp_path):
    script = _write(tmp_path / "cached.py", "import itertools\nCOUNTER = itertools.count()\nVALUE = next(COUNTER)\n")
    first = loader.import_script(script)
    second = loader.import_script(script)
    assert first is second
    spelled_differently = tmp_path / "." / "cached.py"
    assert loader.import_script(spelled_differently) is first


def test_import_script_distinguishes_same_stem_in_different_folders(tmp_path):
    one = _write(tmp_path / "one" / "tool.py", "WHO = 'one'\n")
    two = _write(tmp_path / "two" / "tool.py", "WHO = 'two'\n")
    first, second = loader.import_script(one), loader.import_script(two)
    assert (first.WHO, second.WHO) == ("one", "two")
    assert first is not second and first.__name__ != second.__name__


def test_import_script_registers_before_executing_and_exposes_the_parent_dir(tmp_path):
    script = _write(
        tmp_path / "probe.py",
        "import os, sys\nREGISTERED = __name__ in sys.modules\nPARENT_ON_PATH = os.path.dirname(os.path.abspath(__file__)) in sys.path\n",
    )
    module = loader.import_script(script)
    assert module.REGISTERED is True and module.PARENT_ON_PATH is True


def test_import_script_removes_the_parent_dir_from_sys_path_afterwards(tmp_path):
    script = _write(tmp_path / "pkgdir" / "tool.py", "X = 1\n")
    parent = str(script.parent.resolve())
    before = list(sys.path)
    assert parent not in sys.path
    loader.import_script(script)
    assert sys.path == before


def test_import_script_leaves_a_parent_that_was_already_on_the_path(tmp_path, monkeypatch):
    script = _write(tmp_path / "pkgdir" / "tool.py", "X = 1\n")
    monkeypatch.syspath_prepend(str(script.parent.resolve()))
    before = list(sys.path)
    loader.import_script(script)
    assert sys.path == before


def test_import_script_failure_cleans_up_and_reraises(tmp_path):
    script = _write(tmp_path / "bad.py", "raise ZeroDivisionError('nope')\n")
    keys_before = set(sys.modules)
    path_before = list(sys.path)
    with pytest.raises(ZeroDivisionError, match="nope"):
        loader.import_script(script)
    assert set(sys.modules) == keys_before
    assert sys.path == path_before


def test_import_script_failure_is_not_cached(tmp_path):
    script = _write(tmp_path / "flaky.py", "raise ValueError('first')\n")
    with pytest.raises(ValueError):
        loader.import_script(script)
    script.write_text("OK = True\n", encoding="utf-8")
    assert loader.import_script(script).OK is True


def test_import_script_without_a_loadable_suffix_raises_import_error(tmp_path):
    script = _write(tmp_path / "prog", "#!/usr/bin/env python3\nX = 1\n")
    with pytest.raises(ImportError):
        loader.import_script(script)


def test_import_script_replaces_a_stale_entry_whose_file_differs(tmp_path):
    script = _write(tmp_path / "stale.py", "VALUE = 'fresh'\n")
    key = "bughunt_tools.stale_" + hashlib.sha1(str(script.resolve()).encode()).hexdigest()[:12]
    stale = types.ModuleType(key)
    stale.__file__ = str(tmp_path / "elsewhere.py")
    stale.VALUE = "stale"
    sys.modules[key] = stale
    try:
        assert loader.import_script(script).VALUE == "fresh"
    finally:
        sys.modules.pop(key, None)


# --------------------------------------------------------------------------------------
# 4.2 run_named, step by step
# --------------------------------------------------------------------------------------

def test_scan_calls_scan_main_with_a_copy_of_argv_and_the_scan_prog(env):
    scan = ScanRecorder(result=5)
    argv = ["x.test", "--ports", "80"]
    assert loader.run_named("scan", argv, tool_file=Path("unused"), scan_main=scan) == 5
    assert scan.calls == [(["x.test", "--ports", "80"], "bughunt scan")]


@pytest.mark.parametrize("raised,expected", [(None, 0), (0, 0), (2, 2), ("bye", 1), (1.5, 1), (130, 130)])
def test_scan_systemexit_goes_through_exit_code(env, raised, expected):
    scan = ScanRecorder(raises=SystemExit(raised))
    assert loader.run_named("scan", [], tool_file=Path("unused"), scan_main=scan) == expected


def test_scan_does_not_catch_other_exceptions(env):
    with pytest.raises(RuntimeError):
        loader.run_named("scan", [], tool_file=Path("unused"), scan_main=ScanRecorder(raises=RuntimeError("boom")))
    with pytest.raises(KeyboardInterrupt):
        loader.run_named("scan", [], tool_file=Path("unused"), scan_main=ScanRecorder(raises=KeyboardInterrupt()))


def test_unknown_module_prints_an_escaped_error_and_returns_2(env):
    env.activate()
    assert loader.run_named("[bold]ghost[/bold]", [], tool_file=Path("unused"), scan_main=forbidden_scan) == 2
    assert "[bold]ghost[/bold]" in env.rich_text  # markup in the typed name is shown literally
    assert "Unknown" in env.rich_text


@pytest.mark.parametrize("name", ["tcurl"])
def test_disabled_reference_returns_2_without_locating_a_script(env, monkeypatch, name):
    def boom(*args, **kwargs):
        raise AssertionError("locate_script must not run for a disabled tool")

    monkeypatch.setattr(loader, "locate_script", boom)
    monkeypatch.setattr(loader, "DISABLED_REFERENCES", frozenset({name}))
    env.activate()
    assert loader.run_named(name, ["--help"], tool_file=Path("unused"), scan_main=forbidden_scan) == 2
    assert "disabled" in env.rich_text and name in env.rich_text


def test_missing_program_reports_where_it_looked_and_runs_nothing(env):
    env.activate()
    tool_file = make_project(env.root)
    assert loader.run_named("pulse", ["zzarg-one", "zzarg-two"], tool_file=tool_file, scan_main=forbidden_scan) == 2
    text = env.rich_text.replace("\\", "/")
    assert "pulse/pulse.py" in text
    assert "BUGHUNT_ADDONS" in text
    assert "zzarg-one" in text and "zzarg-two" in text  # arguments that were not forwarded
    assert "bughunt scan pulse" in text  # the escape hatch for a host named pulse


def test_missing_program_without_arguments_lists_none(env):
    env.activate()
    tool_file = make_project(env.root)
    loader.run_named("pulse", [], tool_file=tool_file, scan_main=forbidden_scan)
    assert "not forwarded" not in env.rich_text.lower()


def test_missing_program_via_alias_names_both_the_token_and_the_command(env):
    env.activate()
    tool_file = make_project(env.root)
    assert loader.run_named("crt-scout", [], tool_file=tool_file, scan_main=forbidden_scan) == 2
    text = env.rich_text.replace("\\", "/")
    assert "crt-scout" in text and "ct" in text
    assert "crt-scout/crt-scout.py" in text
    assert "bughunt scan crt-scout" in text


def test_a_python_reference_tool_runs_in_process_with_its_arguments(env):
    assert run_tool(env, PROBE_MAIN, ["a", "b"]) == 0
    probe = json.loads((env.root / "p" / "proj" / "addons" / "pulse" / "probe.json").read_text(encoding="utf-8"))
    assert probe["argv"] == ["a", "b"]
    assert probe["sys_argv"] == ["bughunt pulse", "a", "b"]
    assert probe["parent_on_path"] is True and probe["import_time_parent_on_path"] is True


def test_an_alias_runs_the_canonical_command_and_names_it_in_sys_argv(env):
    assert run_tool(env, PROBE_MAIN, ["x"], name="ct") == 0
    probe_dir = env.root / "p" / "proj" / "addons" / "crt-scout"
    assert json.loads((probe_dir / "probe.json").read_text(encoding="utf-8"))["sys_argv"] == ["bughunt ct", "x"]
    env.activate()
    tool_file = env.root / "p" / "proj" / "bughunt" / "core" / "scanner.py"
    assert loader.run_named("crt-scout", ["y"], tool_file=tool_file, scan_main=forbidden_scan) == 0
    assert json.loads((probe_dir / "probe.json").read_text(encoding="utf-8"))["sys_argv"] == ["bughunt ct", "y"]


def test_sys_argv_and_sys_path_are_restored_after_the_call(env):
    before_argv, before_path = list(sys.argv), list(sys.path)
    assert run_tool(env, PROBE_MAIN, ["a"]) == 0
    assert sys.argv == before_argv and sys.path == before_path


def test_sys_argv_and_sys_path_are_restored_when_main_raises(env):
    before_argv, before_path = list(sys.argv), list(sys.path)
    run_tool(env, "def main(argv):\n    raise RuntimeError('boom')\n")
    assert sys.argv == before_argv and sys.path == before_path


def test_main_receives_a_copy_of_argv(env):
    env.activate()
    tool_file = make_project(env.root, {"pulse": "def main(argv):\n    argv.append('mutated')\n    return 0\n"})
    caller_argv = ["a"]
    loader.run_named("pulse", caller_argv, tool_file=tool_file, scan_main=forbidden_scan)
    assert caller_argv == ["a"]


MAIN_SHAPES = [
    ("def main(argv):\n    return None\n", 0),
    ("def main(argv):\n    return 7\n", 7),
    ("def main(argv):\n    return -3\n", -3),
    ("def main(argv):\n    return True\n", 0),
    ("def main(argv):\n    return False\n", 0),
    ("def main(argv):\n    return 'x'\n", 0),
    ("def main(argv):\n    return 2.5\n", 0),
    ("async def main(argv):\n    return 4\n", 4),
    ("async def main(argv):\n    return None\n", 0),
    ("def main(argv):\n    raise SystemExit(9)\n", 9),
    ("def main(argv):\n    raise SystemExit('bye')\n", 1),
    ("def main(argv):\n    raise SystemExit()\n", 0),
    ("def main(argv):\n    raise SystemExit(0)\n", 0),
    ("def main(argv):\n    raise SystemExit(True)\n", 1),
    ("def main(*args):\n    return len(args[0])\n", 2),
    ("def main(*, flag=1):\n    return 6\n", 6),
    ("def main():\n    return 3\n", 3),
    ("def main(argv=None):\n    return len(argv)\n", 2),
    ("def main(argv, extra=5):\n    return len(argv) + extra\n", 7),
    ("import sys\ndef main():\n    return len(sys.argv)\n", 3),
    ("x = 1\n", 2),
    ("main = 5\n", 2),
    ("main = None\n", 2),
]


@pytest.mark.parametrize("source,expected", MAIN_SHAPES, ids=[f"{n:02d}" for n in range(len(MAIN_SHAPES))])
def test_main_result_and_signature_mapping(env, source, expected):
    assert run_tool(env, source, ["a", "b"]) == expected


def test_a_module_without_main_names_the_tool_and_returns_2(env):
    assert run_tool(env, "x = 1\n") == 2
    assert "pulse" in env.rich_text


def test_unexpected_exception_in_main_prints_a_traceback_and_returns_1(env):
    assert run_tool(env, "def main(argv):\n    raise RuntimeError('kaboom marker')\n") == 1
    assert "pulse" in env.rich_text and "failed" in env.rich_text
    assert "RuntimeError" in env.stderr_text and "kaboom marker" in env.stderr_text


def test_policy_blocked_prints_the_message_as_plain_text_and_returns_2(env):
    source = "from bughunt.core import egress\ndef main(argv):\n    raise egress.PolicyBlocked('blocked [bold]marker[/bold] reason')\n"
    assert run_tool(env, source) == 2
    assert "blocked [bold]marker[/bold] reason" in env.rich_text
    assert "Traceback" not in env.stderr_text


def test_keyboard_interrupt_in_main_propagates(env):
    with pytest.raises(KeyboardInterrupt):
        run_tool(env, "def main(argv):\n    raise KeyboardInterrupt\n")


def test_missing_package_at_import_returns_2_and_names_the_package(env):
    assert run_tool(env, "import definitely_missing_pkg_xyz\n") == 2
    assert "definitely_missing_pkg_xyz" in env.rich_text
    assert "Traceback" not in env.stderr_text


def test_other_import_errors_return_1_with_the_script_path_and_a_traceback(env):
    assert run_tool(env, "raise ValueError('import marker')\n") == 1
    text = env.rich_text.replace("\\", "/")
    assert "pulse.py" in text
    assert "ValueError" in env.stderr_text and "import marker" in env.stderr_text


def test_import_failure_leaves_no_module_or_path_behind(env):
    before_modules, before_path = set(sys.modules), list(sys.path)
    run_tool(env, "raise ValueError('x')\n")
    assert set(sys.modules) == before_modules and sys.path == before_path


# builtin modules --------------------------------------------------------------------------

@pytest.fixture
def fake_builtin(monkeypatch, tmp_path):
    import bughunt.modules as modules

    state = {"module": None, "error": None, "loads": []}

    def load_builtin(name):
        state["loads"].append(name)
        if state["error"] is not None:
            raise state["error"]
        return state["module"]

    monkeypatch.setattr(modules, "load_builtin", load_builtin)

    def install(source: str, *, with_file: bool = True):
        module = types.ModuleType("fake_builtin")
        if with_file:
            module.__file__ = str(tmp_path / "fake_builtin.py")
        exec(compile(source, "fake_builtin", "exec"), module.__dict__)
        state["module"] = module

    state["install"] = install
    return state


@pytest.mark.parametrize(
    "source,expected",
    [
        ("def main(argv):\n    return len(argv)\n", 2),
        ("def main(argv):\n    raise SystemExit(4)\n", 4),
        ("def main(argv):\n    raise SystemExit('x')\n", 1),
        ("async def main(argv):\n    return 8\n", 8),
        ("def main(argv):\n    raise ValueError('bad')\n", 1),
        ("x = 1\n", 2),
    ],
)
def test_builtin_modules_use_the_same_main_mapping(env, fake_builtin, source, expected):
    fake_builtin["install"](source)
    env.activate()
    assert loader.run_named("dns", ["a", "b"], tool_file=Path("unused"), scan_main=forbidden_scan) == expected
    assert fake_builtin["loads"] == ["dns"]


def test_builtin_module_without_a_file_attribute_still_runs(env, fake_builtin):
    fake_builtin["install"]("def main(argv):\n    return 0\n", with_file=False)
    env.activate()
    assert loader.run_named("dns", [], tool_file=Path("unused"), scan_main=forbidden_scan) == 0


def test_builtin_sys_argv_names_the_module(env, fake_builtin):
    fake_builtin["install"]("import sys\nSEEN = []\ndef main(argv):\n    SEEN.append(list(sys.argv))\n    return 0\n")
    env.activate()
    loader.run_named("dns", ["a"], tool_file=Path("unused"), scan_main=forbidden_scan)
    assert fake_builtin["module"].SEEN == [["bughunt dns", "a"]]


def test_builtin_load_failure_returns_1_with_a_traceback(env, fake_builtin):
    fake_builtin["error"] = ImportError("cannot load marker")
    env.activate()
    assert loader.run_named("dns", [], tool_file=Path("unused"), scan_main=forbidden_scan) == 1
    assert "dns" in env.rich_text
    assert "cannot load marker" in env.stderr_text


def test_builtin_policy_blocked_returns_2_and_prints_plain_text(env, fake_builtin):
    fake_builtin["install"]("from bughunt.core import egress\ndef main(argv):\n    raise egress.PolicyBlocked('no [x] go')\n")
    env.activate()
    assert loader.run_named("dns", [], tool_file=Path("unused"), scan_main=forbidden_scan) == 2
    assert "no [x] go" in env.rich_text


def test_builtin_keyboard_interrupt_propagates(env, fake_builtin):
    fake_builtin["install"]("def main(argv):\n    raise KeyboardInterrupt\n")
    env.activate()
    with pytest.raises(KeyboardInterrupt):
        loader.run_named("dns", [], tool_file=Path("unused"), scan_main=forbidden_scan)


def test_a_builtin_module_wins_over_any_addon_with_the_same_name(env, fake_builtin):
    fake_builtin["install"]("def main(argv):\n    return 11\n")
    env.activate()
    tool_file = make_project(env.root, {"pulse": "def main(argv):\n    return 99\n"})
    assert loader.run_named("dns", [], tool_file=tool_file, scan_main=forbidden_scan) == 11


def test_the_real_capability_module_runs_through_the_builtin_path(env):
    env.activate()
    assert loader.run_named("engine", ["map"], tool_file=Path("unused"), scan_main=forbidden_scan) == 0
    assert json.loads(env.stdout_text)  # `engine map` prints JSON


# program (non-Python) tools and the policy guard (4.5) --------------------------------------

@pytest.fixture
def enabled_tcurl(monkeypatch):
    """Make `tcurl` a non-Python reference (no .py suffix) so the loader's program branch stays reachable.

    tcurl itself is a Python module now; this stands in for any future program-style reference tool.
    """
    monkeypatch.setattr(catalog, "DISABLED_REFERENCES", frozenset())
    monkeypatch.setattr(loader, "DISABLED_REFERENCES", frozenset(), raising=False)
    monkeypatch.setitem(catalog._TOOL_INDEX, "tcurl", catalog.tool_by_command("tcurl")._replace(script="tcurl"))


def test_run_program_requires_policy_before_touching_subprocess(env, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("subprocess must not be reached without a usable policy")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    env.activate()
    with pytest.raises(egress.PolicyBlocked):
        loader._run_program(Path("anything.sh"), [], "test")


def _program(tmp_path: Path, first_line: str) -> Path:
    script = tmp_path / "prog"
    script.write_text(first_line + "\necho hi\n", encoding="utf-8")
    return script


@pytest.fixture
def recorded_run(monkeypatch):
    calls = []
    outcome = types.SimpleNamespace(returncode=0, error=None)

    def fake_run(command, **kwargs):
        calls.append((list(command), kwargs))
        if outcome.error is not None:
            raise outcome.error
        return types.SimpleNamespace(returncode=outcome.returncode)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls, outcome


def test_run_program_body_runs_a_python_script_with_this_interpreter(env, tmp_path, recorded_run):
    calls, _outcome = recorded_run
    script = _program(tmp_path, "#!/usr/bin/env python3")
    env.activate()
    assert loader._run_program.__wrapped__(script, ["a", "b"], "tool") == 0
    assert calls[0][0] == [sys.executable, str(script), "a", "b"]
    assert calls[0][1].get("check") is False


def test_run_program_body_runs_other_scripts_with_bash(env, tmp_path, recorded_run):
    """Spec 11.10: bare `bash` (a Windows trap) is current behavior; pinned until a shell tool is enabled."""
    calls, _outcome = recorded_run
    script = _program(tmp_path, "#!/bin/bash")
    env.activate()
    loader._run_program.__wrapped__(script, ["x"], "tool")
    assert calls[0][0] == ["bash", str(script), "x"]


@pytest.mark.parametrize("returncode,expected", [(0, 0), (None, 0), (3, 3), (-9, -9)])
def test_run_program_body_returns_the_process_code(env, tmp_path, recorded_run, returncode, expected):
    _calls, outcome = recorded_run
    outcome.returncode = returncode
    env.activate()
    assert loader._run_program.__wrapped__(_program(tmp_path, "#!/bin/bash"), [], "tool") == expected


def test_run_program_body_reports_a_script_it_cannot_read(env, tmp_path, recorded_run):
    calls, _outcome = recorded_run
    env.activate()
    assert loader._run_program.__wrapped__(tmp_path / "missing", [], "tool") == 1
    assert calls == []
    assert "tool" in env.rich_text


def test_run_program_body_reports_a_start_failure(env, tmp_path, recorded_run):
    _calls, outcome = recorded_run
    outcome.error = OSError("no such interpreter")
    env.activate()
    assert loader._run_program.__wrapped__(_program(tmp_path, "#!/bin/bash"), [], "tool") == 1
    assert "no such interpreter" in env.rich_text


def test_run_program_body_lets_keyboard_interrupt_through(env, tmp_path, recorded_run):
    _calls, outcome = recorded_run
    outcome.error = KeyboardInterrupt()
    env.activate()
    with pytest.raises(KeyboardInterrupt):
        loader._run_program.__wrapped__(_program(tmp_path, "#!/bin/bash"), [], "tool")


def test_a_non_python_reference_goes_through_run_program(env, monkeypatch, enabled_tcurl):
    seen = []
    monkeypatch.setattr(loader, "_run_program", lambda script, argv, canonical: seen.append((script.name, list(argv), canonical)) or 5)
    env.activate()
    tool_file = make_project(env.root, {"tcurl": "#!/bin/bash\necho hi\n"})
    assert loader.run_named("tcurl", ["-I"], tool_file=tool_file, scan_main=forbidden_scan) == 5
    assert seen == [("tcurl", ["-I"], "tcurl")]


def test_public_surface_names_exist():
    for name in ("run_named", "import_script", "_run_program", "locate_script", "ScanMain", "exit_code", "looks_like_python"):
        assert hasattr(loader, name), name
