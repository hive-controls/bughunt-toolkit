"""The JSON catalog export: the contract a UI or tool reads."""

import json
import os
import subprocess
import sys
from pathlib import Path

from bughunt.console import catalog_export, options
from bughunt.console.catalog import (
    DISABLED_REFERENCES,
    MODULE_GROUPS,
    REFERENCES,
    locate_script,
)
from bughunt.console.catalog_export import export_catalog
from bughunt.core import scanner

REPO_ROOT = Path(__file__).resolve().parent.parent


def _export() -> dict:
    return export_catalog(
        tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )


def test_export_is_json_serializable_and_well_shaped():
    data = _export()
    text = json.dumps(data)  # must not raise
    assert json.loads(text)["schema_version"] == data["schema_version"]
    assert [p["name"] for p in data["phases"]] == [t.lower() for t, _ in MODULE_GROUPS]


def test_every_module_carries_guidance_and_a_form_or_reason():
    data = _export()
    modules = [m for p in data["phases"] for m in p["modules"]]
    expected = sum(len(members) for _title, members in MODULE_GROUPS)
    assert len(modules) == expected
    for module in modules:
        assert module["when"], f"{module['name']} has no when-line"
        # A module has a usable option form, or an explicit reason it is unavailable.
        assert module["form"] is not None or module.get("unavailable")


def test_scan_form_exposes_options():
    data = _export()
    scan = next(m for p in data["phases"] for m in p["modules"] if m["name"] == "scan")
    assert scan["form"] is not None
    assert isinstance(scan["form"]["options"], list)


def test_disabled_reference_degrades_cleanly(monkeypatch):
    monkeypatch.setattr(catalog_export, "DISABLED_REFERENCES", frozenset({"skiff"}))
    monkeypatch.setattr(options, "DISABLED_REFERENCES", frozenset({"skiff"}))
    data = _export()
    skiff = next(
        m for p in data["phases"] for m in p["modules"] if m["name"] == "skiff"
    )
    assert skiff["disabled"] is True
    assert skiff["form"] is None and skiff["unavailable"]
    tcurl = next(
        m for p in data["phases"] for m in p["modules"] if m["name"] == "tcurl"
    )
    assert tcurl["disabled"] is False and tcurl["form"] is not None


def test_skiff_reference_is_live_once_re_enabled():
    data = _export()
    skiff = next(
        m for p in data["phases"] for m in p["modules"] if m["name"] == "skiff"
    )
    assert skiff["disabled"] is False
    assert skiff["form"] is not None and not skiff.get("unavailable")


def test_source_checkout_finds_repo_root_addons_without_env(monkeypatch):
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    shipped = [
        tool
        for tool in REFERENCES
        if (REPO_ROOT / "addons" / tool.folder / tool.script).is_file()
    ]
    assert len(shipped) >= 7
    for tool in shipped:
        located = locate_script(tool, Path(scanner.__file__))
        expected = (REPO_ROOT / "addons" / tool.folder / tool.script).resolve()
        assert located is not None and located.resolve() == expected, tool.command


def test_catalog_gives_enabled_reference_modules_a_form_without_env(monkeypatch):
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    modules = {m["name"]: m for p in _export()["phases"] for m in p["modules"]}
    for tool in REFERENCES:
        if tool.command not in DISABLED_REFERENCES:
            assert modules[tool.command]["form"] is not None, tool.command


def test_python_dash_m_runs_reference_module_without_env(tmp_path):
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("BUGHUNT_")
    }
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["BUGHUNT_SCOPE"] = str(tmp_path / "scope")
    completed = subprocess.run(
        [sys.executable, "-m", "bughunt", "pulse", "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stdout[-400:] + completed.stderr[-400:]


def test_v2_operation_contracts_cover_the_parser_inventory():
    from bughunt.core import adapters

    data = _export()
    assert data["schema_version"] == 2
    modules = {
        module["name"]: module
        for phase in data["phases"]
        for module in phase["modules"]
    }
    assert len(modules) == 45
    for name, module in modules.items():
        assert module["id"] == name
        assert {row["id"] for row in module["operations"]} == set(
            adapters.operation_names(name)
        )
        for row in module["operations"]:
            assert row["result_schema"] == "urn:bughunt:result:1"
            assert row["side_effect"] in {
                "read",
                "write",
                "network",
                "conditional",
                "interactive",
            }
            assert row["noninteractive_equivalent"]
            assert isinstance(row["supports_dry_run"], bool)
    capture = next(
        row for row in modules["exchange"]["operations"] if row["id"] == "import-raw"
    )
    assert capture["input_artifacts"] == {"url": "urls"}
    assert capture["output_artifacts"] == ["exchanges"]
    discover = modules["discover"]["operations"][0]
    assert discover["input_artifacts"] == {"exchange_id": "exchanges"}
    mutation = next(
        row for row in modules["policy"]["operations"] if row["id"] == "import"
    )
    assert not mutation["pipeline_eligible"]
    assert mutation["pipeline_restriction"] == "configuration-mutation"
