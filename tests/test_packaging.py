"""Clean core-wheel and full-source installation contracts."""

import importlib
import json
import os
import shutil
import site
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

from public_tree_support import REPO_ROOT, public_tree_paths

LICENSE_FILES = ("LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.md")
ADDON_COMMANDS = (
    "pulse",
    "ct",
    "carve",
    "phish",
    "ioc",
    "chroma",
    "urlscan",
    "tcurl",
    "skiff",
)


def test_console_script_target_is_importable_and_callable():
    import tomllib

    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    module_name, _, attribute = project["project"]["scripts"]["bughunt"].partition(":")
    assert callable(getattr(importlib.import_module(module_name), attribute))


def _checked(command, *, cwd=None, env=None):
    completed = subprocess.run(
        list(map(str, command)),
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if completed.returncode:
        raise RuntimeError(
            f"Required command failed ({completed.returncode}): {completed.stderr[-1000:]}"
        )
    return completed


def _copy_source(destination, *, complete):
    destination.mkdir()
    if complete:
        paths = public_tree_paths()
    else:
        paths = [
            path
            for path in public_tree_paths()
            if path.startswith("bughunt/")
            or path in {"pyproject.toml", "README.md", *LICENSE_FILES}
        ]
    for filename in LICENSE_FILES:
        if filename not in paths:
            raise RuntimeError("Required distribution licensing file missing")
    for path in paths:
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / path, target)
    return destination


def _build_wheel(workdir):
    source = _copy_source(workdir / "source", complete=False)
    wheel_dir = workdir / "wheels"
    _checked(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            source,
            "--no-deps",
            "-w",
            wheel_dir,
        ],
        cwd=workdir,
    )
    wheels = list(wheel_dir.glob("bughunt-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("Expected exactly one built wheel")
    return wheels[0]


def test_required_wheel_build_failure_is_an_error(monkeypatch, tmp_path):
    from types import SimpleNamespace

    original_run = subprocess.run

    def fail_wheel(command, *args, **kwargs):
        if list(map(str, command))[1:4] == ["-m", "pip", "wheel"]:
            return SimpleNamespace(
                returncode=1, stdout="", stderr="synthetic build failure"
            )
        return original_run(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fail_wheel)
    try:
        _build_wheel(tmp_path)
    except BaseException as failure:
        assert isinstance(failure, RuntimeError), (
            "Build failure became a skip or another exception"
        )
    else:
        pytest.fail("Required wheel build failure was accepted")


def _clean_environment(run_dir):
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("BUGHUNT_")
        and key
        not in {
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONUSERBASE",
            "PYTHONUTF8",
            "PYTHONIOENCODING",
            "PIP_TARGET",
            "PIP_PREFIX",
        }
    }
    environment.update(
        PYTHONNOUSERSITE="1",
        NO_COLOR="1",
        BUGHUNT_SCOPE=str(run_dir / "workspace"),
    )
    return environment


def _install_in_venv(workdir, arguments):
    directory = workdir / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(directory)
    bin_dir = directory / ("Scripts" if os.name == "nt" else "bin")
    suffix = ".exe" if os.name == "nt" else ""
    interpreter = bin_dir / f"python{suffix}"
    run_dir = workdir / "run"
    run_dir.mkdir()
    environment = _clean_environment(run_dir)
    _checked(
        [interpreter, "-m", "pip", "install", *arguments], cwd=run_dir, env=environment
    )
    _checked([interpreter, "-m", "pip", "check"], cwd=run_dir, env=environment)
    return interpreter, bin_dir / f"bughunt{suffix}", run_dir, environment


def test_required_install_failure_is_an_error(monkeypatch, tmp_path):
    from types import SimpleNamespace

    original_run = subprocess.run

    def fail_install(command, *args, **kwargs):
        if list(map(str, command))[1:4] == ["-m", "pip", "install"]:
            return SimpleNamespace(
                returncode=1, stdout="", stderr="synthetic install failure"
            )
        return original_run(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fail_install)
    with pytest.raises(RuntimeError, match="Required command failed"):
        _install_in_venv(tmp_path, ["synthetic-package"])


def _assert_isolated(interpreter, run_dir, environment, expected_package_root):
    program = (
        "import bughunt,json,site,sys;"
        "print(json.dumps({'file':bughunt.__file__,'paths':sys.path,"
        "'usersite':site.ENABLE_USER_SITE,'prefix':sys.prefix,'base':sys.base_prefix}))"
    )
    report = json.loads(
        _checked(
            [interpreter, "-I", "-c", program], cwd=run_dir, env=environment
        ).stdout
    )
    assert (
        Path(report["file"]).resolve().is_relative_to(expected_package_root.resolve())
    )
    assert report["usersite"] is False
    assert report["prefix"] != report["base"]
    host_paths = {
        os.path.normcase(str(Path(path).resolve())) for path in site.getsitepackages()
    }
    # Windows includes the shared interpreter prefix, not only package directories.
    host_paths.discard(os.path.normcase(str(Path(report["base"]).resolve())))
    assert not host_paths.intersection(
        os.path.normcase(str(Path(path).resolve())) for path in report["paths"]
    )


@pytest.mark.parametrize("windows_layout", [True, False], ids=["windows", "posix"])
@pytest.mark.parametrize(
    "leak_host_packages", [False, True], ids=["isolated", "leaked"]
)
def test_isolation_check_distinguishes_shared_base_from_host_packages(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    windows_layout: bool,
    leak_host_packages: bool,
) -> None:
    base = tmp_path / "Python312"
    package_suffix = (
        "Lib/site-packages" if windows_layout else "lib/python3.12/site-packages"
    )
    host_packages = base / package_suffix
    isolated = tmp_path / "venv"
    isolated_packages = isolated / package_suffix
    host_paths = [str(host_packages)]
    if windows_layout:
        host_paths.insert(0, str(base))
    paths = [str(base), str(base / "Lib"), str(isolated_packages)]
    if leak_host_packages:
        paths.append(str(host_packages))
    report = {
        "file": str(isolated_packages / "bughunt/__init__.py"),
        "paths": paths,
        "usersite": False,
        "prefix": str(isolated),
        "base": str(base),
    }
    monkeypatch.setattr(site, "getsitepackages", lambda: host_paths)
    monkeypatch.setattr(
        sys.modules[__name__],
        "_checked",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, json.dumps(report)),
    )
    if leak_host_packages:
        with pytest.raises(AssertionError):
            _assert_isolated(isolated / "python", tmp_path, {}, isolated)
    else:
        _assert_isolated(isolated / "python", tmp_path, {}, isolated)


def _exercise_core(script, run_dir, environment):
    for arguments in (
        ("--help",),
        ("version",),
        ("modules",),
        ("scope", "init"),
        ("scope", "list"),
        ("catalog",),
    ):
        result = _checked([script, *arguments], cwd=run_dir, env=environment)
        assert "Traceback" not in result.stderr
        if arguments == ("catalog",):
            assert isinstance(json.loads(result.stdout), dict)


@pytest.fixture(scope="module")
def core_install(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("core-wheel")
    wheel = _build_wheel(workdir)
    interpreter, script, run_dir, environment = _install_in_venv(workdir, [str(wheel)])
    return workdir, wheel, interpreter, script, run_dir, environment


def test_installed_core_wheel_runs_with_only_declared_dependencies(core_install):
    workdir, _, interpreter, script, run_dir, environment = core_install
    _assert_isolated(interpreter, run_dir, environment, workdir / "venv")
    _exercise_core(script, run_dir, environment)


def test_wheel_carries_exact_licenses_and_integration_helper(core_install):
    _, wheel, interpreter, _, run_dir, environment = core_install
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        for filename in LICENSE_FILES:
            packaged = [
                name for name in names if name.endswith("/licenses/" + filename)
            ]
            assert len(packaged) == 1, filename
            assert archive.read(packaged[0]) == (REPO_ROOT / filename).read_bytes()
        assert (
            archive.read("bughunt/integrations/browser_consumer.cjs")
            == (REPO_ROOT / "bughunt/integrations/browser_consumer.cjs").read_bytes()
        )
    program = (
        "from importlib.resources import files;"
        "assert files('bughunt.integrations').joinpath('browser_consumer.cjs').read_bytes()"
    )
    _checked([interpreter, "-I", "-c", program], cwd=run_dir, env=environment)


def test_full_public_source_install_includes_working_addons(tmp_path):
    source = _copy_source(tmp_path / "source", complete=True)
    _checked(["git", "init", "-q"], cwd=source)
    _checked(["git", "add", "--all"], cwd=source)
    interpreter, script, run_dir, environment = _install_in_venv(
        tmp_path,
        [
            "-r",
            str(source / "requirements-hardened.txt"),
            "-r",
            str(source / "requirements-dev.txt"),
            "-e",
            str(source) + "[pipeline-yaml,tor]",
        ],
    )
    _assert_isolated(interpreter, run_dir, environment, source / "bughunt")
    _exercise_core(script, run_dir, environment)
    for command in ADDON_COMMANDS:
        _checked([script, command, "--help"], cwd=run_dir, env=environment)
    page = run_dir / "page.html"
    page.write_text(
        '<a href="https://example.test/owned-result">owned</a>', encoding="utf-8"
    )
    output = run_dir / "endpoints.json"
    _checked(
        [script, "carve", page, "--format", "json", "-o", output, "--quiet"],
        cwd=run_dir,
        env=environment,
    )
    assert "owned-result" in json.dumps(json.loads(output.read_text(encoding="utf-8")))
    _checked(
        [interpreter, source / "bin/http_port_probe.py", "--help"],
        cwd=run_dir,
        env=environment,
    )
    _checked(
        [interpreter, source / "scripts/check_python_quality.py"],
        cwd=source,
        env=environment,
    )
    _checked(
        [interpreter, "-m", "pytest", "tests/test_public_tree.py", "-q"],
        cwd=source,
        env=environment,
    )
